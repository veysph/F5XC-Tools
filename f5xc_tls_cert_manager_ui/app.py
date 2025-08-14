#!/usr/bin/env python3
"""
F5 Distributed Cloud TLS Certificate Management Web Application

A Flask web application that provides a web interface for managing Let's Encrypt
TLS certificates on the F5 Distributed Cloud platform.
"""

import json
import os
import base64
import requests
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import re
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask.logging import default_handler
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from werkzeug.security import safe_join

from f5xc_tls_cert_manager import F5CertificateManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('f5xc_cert_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Production configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max request size
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session timeout
)

# Production configuration paths
BASE_DIR = Path(__file__).parent
CERTS_DIR = Path(os.environ.get('CERTS_DIR', BASE_DIR / 'certs'))
CONFIG_FILE = Path(os.environ.get('CONFIG_FILE', BASE_DIR / 'config.json'))
TRACKING_FILE = Path(os.environ.get('TRACKING_FILE', BASE_DIR / 'certificate_tracking.json'))

# Ensure required directories exist
CERTS_DIR.mkdir(exist_ok=True)
BASE_DIR.mkdir(exist_ok=True)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # CSP for additional security
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
        "font-src 'self' cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response

# Input validation helper
def validate_input(data: str, max_length: int = 1000, allowed_chars: str = None) -> bool:
    """Validate input data for security."""
    if not data or len(data) > max_length:
        return False
    if allowed_chars:
        return all(c in allowed_chars for c in data)
    return True


def validate_f5xc_name(name: str) -> Dict[str, Any]:
    """Validate F5XC certificate name according to DNS1035 Label rules."""
    if not name or len(name) == 0:
        return {'valid': False, 'error': 'Name is required'}
    
    if len(name) >= 64:
        return {'valid': False, 'error': 'Name must be less than 64 characters'}
    
    # DNS1035 Label: [a-z]([-a-z0-9]*[a-z0-9])?
    dns1035_pattern = r'^[a-z]([-a-z0-9]*[a-z0-9])?$'
    if not re.match(dns1035_pattern, name):
        return {
            'valid': False,
            'error': 'Name must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens. Cannot end with a hyphen.'
        }
    
    return {'valid': True}


def load_certificate_tracking() -> Dict[str, Any]:
    """Load certificate tracking data from file."""
    try:
        if TRACKING_FILE.exists():
            with open(TRACKING_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading tracking data: {e}")
    
    # Return default structure
    return {
        'certificates': {},
        'last_updated': datetime.now().isoformat()
    }


def save_certificate_tracking(tracking_data: Dict[str, Any]) -> None:
    """Save certificate tracking data to file."""
    try:
        tracking_data['last_updated'] = datetime.now().isoformat()
        with open(TRACKING_FILE, 'w') as f:
            json.dump(tracking_data, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving tracking data: {e}")


def track_certificate_operation(operation: str, cert_name: str, directory_name: str, 
                               namespace: str, tenant: str, success: bool = True, 
                               f5xc_timestamps: Dict[str, str] = None) -> None:
    """Track a certificate operation (create/replace/delete)."""
    tracking_data = load_certificate_tracking()
    
    # Create unique key for this certificate deployment
    cert_key = f"{tenant}:{namespace}:{cert_name}"
    
    operation_record = {
        'operation': operation,
        'certificate_name': cert_name,
        'directory_name': directory_name,
        'namespace': namespace,
        'tenant': tenant,
        'timestamp': datetime.now().isoformat(),
        'success': success
    }
    
    # Add F5XC timestamps if provided (for found_existing operations)
    if f5xc_timestamps:
        operation_record.update({
            'f5xc_creation_timestamp': f5xc_timestamps.get('creation_timestamp'),
            'f5xc_modification_timestamp': f5xc_timestamps.get('modification_timestamp'),
            'f5xc_most_recent_timestamp': f5xc_timestamps.get('most_recent')
        })
        
        # Use F5XC timestamp as the operation timestamp for existing certificates
        if operation == 'found_existing' and f5xc_timestamps.get('most_recent'):
            operation_record['timestamp'] = f5xc_timestamps['most_recent']
    
    if operation == 'delete' and success:
        # Remove from active certificates if deletion was successful
        if cert_key in tracking_data['certificates']:
            # Keep a record of the deletion in history
            if 'history' not in tracking_data:
                tracking_data['history'] = []
            
            deleted_cert = tracking_data['certificates'][cert_key].copy()
            deleted_cert['deleted_at'] = datetime.now().isoformat()
            tracking_data['history'].append(deleted_cert)
            
            # Remove from active certificates
            del tracking_data['certificates'][cert_key]
            
        # Also add the delete operation to history
        if 'history' not in tracking_data:
            tracking_data['history'] = []
        tracking_data['history'].append(operation_record)
    else:
        # For create/replace operations, update the active certificates
        if success:
            tracking_data['certificates'][cert_key] = operation_record
        
        # Keep operation history
        if 'history' not in tracking_data:
            tracking_data['history'] = []
        tracking_data['history'].append(operation_record)
    
    # Limit history to last 100 operations
    if 'history' in tracking_data and len(tracking_data['history']) > 100:
        tracking_data['history'] = tracking_data['history'][-100:]
    
    save_certificate_tracking(tracking_data)


def get_certificate_deployments(directory_name: str = None) -> List[Dict[str, Any]]:
    """Get F5XC deployments for a certificate directory."""
    tracking_data = load_certificate_tracking()
    
    if directory_name:
        # Return deployments for specific certificate
        return [
            cert_info for cert_info in tracking_data['certificates'].values()
            if cert_info['directory_name'] == directory_name
        ]
    else:
        # Return all deployments
        return list(tracking_data['certificates'].values())


class CertificateParser:
    """Parse and extract information from certificate files."""
    
    def __init__(self, certs_directory: str = None):
        self.certs_dir = Path(certs_directory) if certs_directory else CERTS_DIR
    
    def parse_certificate(self, cert_path: Path) -> Dict[str, Any]:
        """Parse a certificate file and extract relevant information."""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Parse the certificate
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Extract subject alternative names (domains)
            san_domains = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_domains = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            # Extract common name from subject
            common_name = None
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            # Calculate days until expiry (handle different cryptography versions)
            now = datetime.now(timezone.utc)
            try:
                # Try new API (cryptography >= 41.0.0)
                not_valid_after = cert.not_valid_after_utc
                not_valid_before = cert.not_valid_before_utc
            except AttributeError:
                # Fall back to old API
                not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            
            days_until_expiry = (not_valid_after - now).days
            
            return {
                'subject_common_name': common_name,
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_valid_before': not_valid_before.isoformat(),
                'not_valid_after': not_valid_after.isoformat(),
                'days_until_expiry': days_until_expiry,
                'san_domains': san_domains,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'version': cert.version.name,
                'is_expired': days_until_expiry < 0,
                'expires_soon': 0 <= days_until_expiry <= 30
            }
        except Exception as e:
            return {'error': f'Failed to parse certificate: {str(e)}'}
    
    def scan_certificates(self) -> List[Dict[str, Any]]:
        """Scan the certs directory and return information about all certificates."""
        certificates = []
        
        if not self.certs_dir.exists():
            return certificates
        
        for cert_dir in self.certs_dir.iterdir():
            if cert_dir.is_dir():
                fullchain_path = cert_dir / 'fullchain.pem'
                privkey_path = cert_dir / 'privkey.pem'
                
                if fullchain_path.exists():
                    cert_info = self.parse_certificate(fullchain_path)
                    cert_info.update({
                        'directory_name': cert_dir.name,
                        'fullchain_path': str(fullchain_path),
                        'privkey_path': str(privkey_path) if privkey_path.exists() else None,
                        'has_private_key': privkey_path.exists(),
                        'last_modified': datetime.fromtimestamp(fullchain_path.stat().st_mtime).isoformat(),
                        'f5xc_deployments': get_certificate_deployments(cert_dir.name)
                    })
                    certificates.append(cert_info)
        
        return sorted(certificates, key=lambda x: x.get('not_valid_after', ''))


@app.route('/')
def index():
    """Main dashboard showing all certificates."""
    return render_template('index.html')


@app.route('/api/certificates')
def get_certificates():
    """API endpoint to get all certificate information."""
    parser = CertificateParser()
    certificates = parser.scan_certificates()
    return jsonify(certificates)


@app.route('/api/certificate/<path:cert_name>')
def get_certificate_details(cert_name):
    """API endpoint to get detailed information about a specific certificate."""
    parser = CertificateParser()
    cert_dir = parser.certs_dir / cert_name
    
    if not cert_dir.exists() or not cert_dir.is_dir():
        return jsonify({'error': 'Certificate not found'}), 404
    
    fullchain_path = cert_dir / 'fullchain.pem'
    if not fullchain_path.exists():
        return jsonify({'error': 'Certificate file not found'}), 404
    
    cert_info = parser.parse_certificate(fullchain_path)
    cert_info.update({
        'directory_name': cert_name,
        'fullchain_path': str(fullchain_path),
        'privkey_path': str(cert_dir / 'privkey.pem'),
        'has_private_key': (cert_dir / 'privkey.pem').exists()
    })
    
    return jsonify(cert_info)


@app.route('/api/f5xc/create', methods=['POST'])
def create_f5xc_certificate():
    """Create a certificate on F5 Distributed Cloud."""
    data = request.get_json()
    cert_name = data.get('certificate_name')
    directory_name = data.get('directory_name')
    custom_settings = data.get('settings', {})
    
    if not cert_name or not directory_name:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    # Validate certificate name
    name_validation = validate_f5xc_name(cert_name)
    if not name_validation['valid']:
        return jsonify({'error': f'Invalid certificate name: {name_validation["error"]}'}), 400
    
    # Create temporary config for this operation
    config = create_temp_config(cert_name, directory_name, custom_settings)
    
    try:
        manager = F5CertificateManager(config)
        manager._validate_config('create')
        success = manager.create_certificate()
        
        # Track the operation
        track_certificate_operation(
            operation='create',
            cert_name=cert_name,
            directory_name=directory_name,
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=success
        )
        
        if success:
            return jsonify({'message': f'Certificate {cert_name} created successfully on F5XC'})
        else:
            return jsonify({'error': 'Failed to create certificate'}), 500
    except Exception as e:
        # Track failed operation
        track_certificate_operation(
            operation='create',
            cert_name=cert_name,
            directory_name=directory_name,
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=False
        )
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary config file
        try:
            os.unlink(config)
        except Exception:
            pass


@app.route('/api/f5xc/replace', methods=['PUT'])
def replace_f5xc_certificate():
    """Replace a certificate on F5 Distributed Cloud."""
    data = request.get_json()
    cert_name = data.get('certificate_name')
    directory_name = data.get('directory_name')
    custom_settings = data.get('settings', {})
    
    if not cert_name or not directory_name:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    # Validate certificate name
    name_validation = validate_f5xc_name(cert_name)
    if not name_validation['valid']:
        return jsonify({'error': f'Invalid certificate name: {name_validation["error"]}'}), 400
    
    # Create temporary config for this operation
    config = create_temp_config(cert_name, directory_name, custom_settings)
    
    try:
        manager = F5CertificateManager(config)
        manager._validate_config('replace')
        success = manager.replace_certificate()
        
        # Track the operation
        track_certificate_operation(
            operation='replace',
            cert_name=cert_name,
            directory_name=directory_name,
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=success
        )
        
        if success:
            return jsonify({'message': f'Certificate {cert_name} replaced successfully on F5XC'})
        else:
            return jsonify({'error': 'Failed to replace certificate'}), 500
    except Exception as e:
        # Track failed operation
        track_certificate_operation(
            operation='replace',
            cert_name=cert_name,
            directory_name=directory_name,
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=False
        )
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary config file
        try:
            os.unlink(config)
        except Exception:
            pass


@app.route('/api/f5xc/delete', methods=['DELETE'])
def delete_f5xc_certificate():
    """Delete a certificate from F5 Distributed Cloud."""
    data = request.get_json()
    cert_name = data.get('certificate_name')
    custom_settings = data.get('settings', {})
    
    if not cert_name:
        return jsonify({'error': 'Missing certificate name'}), 400
    
    # Validate certificate name
    name_validation = validate_f5xc_name(cert_name)
    if not name_validation['valid']:
        return jsonify({'error': f'Invalid certificate name: {name_validation["error"]}'}), 400
    
    # Create temporary config for this operation
    config = create_temp_config(cert_name, '', custom_settings)
    
    try:
        manager = F5CertificateManager(config)
        manager._validate_config('delete')
        success = manager.delete_certificate()
        
        # Track the operation
        track_certificate_operation(
            operation='delete',
            cert_name=cert_name,
            directory_name='',  # No directory for delete operations
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=success
        )
        
        if success:
            return jsonify({'message': f'Certificate {cert_name} deleted successfully from F5XC'})
        else:
            return jsonify({'error': 'Failed to delete certificate'}), 500
    except Exception as e:
        # Track failed operation
        track_certificate_operation(
            operation='delete',
            cert_name=cert_name,
            directory_name='',
            namespace=custom_settings.get('namespace', 'shared'),
            tenant=custom_settings.get('tenant_name', 'unknown'),
            success=False
        )
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary config file
        try:
            os.unlink(config)
        except Exception:
            pass


def extract_p12_for_requests(p12_path: str, p12_password: str):
    """Extract certificate and key from P12 file for requests library."""
    import tempfile
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    
    try:
        # Load P12 certificate
        with open(p12_path, 'rb') as f:
            p12_data = f.read()
        
        # Parse P12 certificate
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, p12_password.encode('utf-8')
        )
        
        # Create temporary files for cert and key
        cert_fd, cert_path = tempfile.mkstemp(suffix='.pem', prefix='f5xc_cert_')
        key_fd, key_path = tempfile.mkstemp(suffix='.pem', prefix='f5xc_key_')
        
        try:
            # Write certificate to temporary file
            with os.fdopen(cert_fd, 'wb') as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # Write private key to temporary file
            with os.fdopen(key_fd, 'wb') as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            return cert_path, key_path
            
        except Exception as e:
            # Clean up on error
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except Exception:
                pass
            raise e
            
    except Exception as e:
        raise Exception(f"Failed to extract P12 certificate: {str(e)}")


def get_f5xc_session(config_path: str = None):
    """Create an authenticated session for F5XC API calls."""
    try:
        # Load configuration
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        
        # Extract P12 certificate for requests
        p12_path = config.get('client_cert_path')
        p12_password = config.get('client_cert_password')
        
        if not p12_path or not p12_password:
            raise Exception("P12 certificate path and password are required")
        
        if not os.path.exists(p12_path):
            raise Exception(f"P12 certificate file not found: {p12_path}")
        
        # Extract certificate and key
        cert_path, key_path = extract_p12_for_requests(p12_path, p12_password)
        
        # Create authenticated session
        session = requests.Session()
        session.cert = (cert_path, key_path)
        session.verify = True
        
        # Add headers
        session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'F5XC-TLS-Certificate-Manager/1.0'
        })
        
        # Store temp file paths for cleanup
        session._temp_cert_path = cert_path
        session._temp_key_path = key_path
        
        return session, config
    except Exception as e:
        raise Exception(f"Failed to create F5XC session: {str(e)}")


def cleanup_f5xc_session(session: requests.Session):
    """Clean up temporary certificate files."""
    try:
        if hasattr(session, '_temp_cert_path'):
            os.unlink(session._temp_cert_path)
        if hasattr(session, '_temp_key_path'):
            os.unlink(session._temp_key_path)
    except Exception:
        pass


def list_f5xc_certificates(namespace: str, tenant_name: str, session: requests.Session) -> List[Dict[str, Any]]:
    """List all certificates in a specific F5XC namespace."""
    try:
        url = f"https://{tenant_name}.console.ves.volterra.io/api/config/namespaces/{namespace}/certificates"
        
        response = session.get(url)
        response.raise_for_status()
        
        data = response.json()
        return data.get('items', [])
    except Exception as e:
        raise Exception(f"Failed to list F5XC certificates: {str(e)}")


def get_f5xc_certificate_details(namespace: str, cert_name: str, tenant_name: str, session: requests.Session) -> Dict[str, Any]:
    """Get detailed information about a specific F5XC certificate using official API format."""
    try:
        # Use the official API documentation format without response_format parameter
        url = f"https://{tenant_name}.console.ves.volterra.io/api/config/namespaces/{namespace}/certificates/{cert_name}"
        
        logger.debug(f"API call: GET {url}")
        
        response = session.get(url)
        logger.debug(f"Response status: {response.status_code}")
        
        response.raise_for_status()
        
        cert_data = response.json()
        logger.debug(f"Response keys: {list(cert_data.keys()) if cert_data else 'None'}")
        
        return cert_data
    except Exception as e:
        logger.error(f"API call failed: {str(e)}")
        raise Exception(f"Failed to get F5XC certificate details: {str(e)}")


def extract_certificate_domains(cert_details: Dict[str, Any]) -> List[str]:
    """Extract domains from F5XC certificate details using correct spec.infos structure."""
    domains = []
    
    try:
        logger.debug("Extracting domains from certificate structure")
        logger.debug(f"Certificate keys: {list(cert_details.keys()) if cert_details else 'None'}")
        
        # Method 1: Try spec.infos structure (correct standard API response)
        spec = cert_details.get('spec', {})
        if spec:
            logger.debug(f"Found spec with keys: {list(spec.keys())}")
            infos = spec.get('infos', [])
            if infos:
                logger.debug(f" Found {len(infos)} info entries in spec")
                for i, info in enumerate(infos):
                    logger.debug(f" Info {i} keys: {list(info.keys()) if info else 'None'}")
                    
                    # Extract common_name
                    common_name = info.get('common_name')
                    if common_name and common_name not in domains:
                        domains.append(common_name)
                        logger.debug(f" Added common_name: {common_name}")
                    
                    # Extract subject_alternative_names
                    san_list = info.get('subject_alternative_names', [])
                    logger.debug(f" Found {len(san_list)} SANs: {san_list}")
                    for san in san_list:
                        if san and san not in domains:
                            domains.append(san)
                            logger.debug(f" Added SAN: {san}")
            else:
                logger.debug(f" No infos found in spec")
        else:
            logger.debug(f" No spec found in certificate")
        
        # Method 2: Try get_spec.infos structure (fallback for response_format=0)
        if not domains:
            get_spec = cert_details.get('get_spec', {})
            if get_spec:
                logger.debug(f" Trying get_spec fallback with keys: {list(get_spec.keys())}")
                infos = get_spec.get('infos', [])
                if infos:
                    logger.debug(f" Found {len(infos)} info entries in get_spec")
                    for i, info in enumerate(infos):
                        logger.debug(f" Info {i} keys: {list(info.keys()) if info else 'None'}")
                        
                        # Extract common_name
                        common_name = info.get('common_name')
                        if common_name and common_name not in domains:
                            domains.append(common_name)
                            logger.debug(f" Added common_name: {common_name}")
                        
                        # Extract subject_alternative_names
                        san_list = info.get('subject_alternative_names', [])
                        for san in san_list:
                            if san and san not in domains:
                                domains.append(san)
                                logger.debug(f" Added SAN: {san}")
        
        # Method 3: Try to extract from certificate_url (base64 encoded certificate)
        if not domains:
            cert_url = None
            # Try both spec and get_spec for certificate_url
            if spec:
                cert_url = spec.get('certificate_url', '')
            if not cert_url and cert_details.get('get_spec'):
                cert_url = cert_details.get('get_spec', {}).get('certificate_url', '')
                
            if cert_url and cert_url.startswith('string:///'):
                logger.debug(f" Found certificate_url, attempting to decode")
                try:
                    # Extract base64 part after 'string:///'
                    base64_cert = cert_url[len('string:///'):]
                    cert_pem = base64.b64decode(base64_cert).decode('utf-8')
                    
                    # Parse the certificate to extract domains
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                    
                    # Extract common name
                    for attribute in cert.subject:
                        if attribute.oid == x509.NameOID.COMMON_NAME:
                            if attribute.value and attribute.value not in domains:
                                domains.append(attribute.value)
                                logger.debug(f" Added decoded CN: {attribute.value}")
                    
                    # Extract SAN
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        for name in san_ext.value:
                            if name.value and name.value not in domains:
                                domains.append(name.value)
                                logger.debug(f" Added decoded SAN: {name.value}")
                    except x509.ExtensionNotFound:
                        logger.debug(f" No SAN extension found in decoded certificate")
                        
                except Exception as e:
                    logger.debug(f" Failed to decode certificate_url: {e}")
        
        logger.debug(f"    - Final extracted domains: {domains}")
                
    except Exception as e:
        logger.debug(f"    - Warning: Failed to extract domains from certificate: {e}")
    
    return domains


def extract_certificate_timestamps(cert_details: Dict[str, Any]) -> Dict[str, str]:
    """Extract creation and modification timestamps from F5XC certificate."""
    timestamps = {
        'creation_timestamp': None,
        'modification_timestamp': None,
        'most_recent': None
    }
    
    try:
        system_metadata = cert_details.get('system_metadata', {})
        
        # Extract creation timestamp
        creation_ts = system_metadata.get('creation_timestamp')
        if creation_ts:
            timestamps['creation_timestamp'] = creation_ts
        
        # Extract modification timestamp  
        modification_ts = system_metadata.get('modification_timestamp')
        if modification_ts:
            timestamps['modification_timestamp'] = modification_ts
        
        # Determine most recent timestamp
        if creation_ts and modification_ts:
            # Compare timestamps to find the most recent
            from datetime import datetime, timezone
            try:
                creation_dt = datetime.fromisoformat(creation_ts.replace('Z', '+00:00'))
                modification_dt = datetime.fromisoformat(modification_ts.replace('Z', '+00:00'))
                timestamps['most_recent'] = modification_ts if modification_dt > creation_dt else creation_ts
            except Exception:
                # If parsing fails, use modification timestamp as it's typically more recent
                timestamps['most_recent'] = modification_ts
        elif modification_ts:
            timestamps['most_recent'] = modification_ts
        elif creation_ts:
            timestamps['most_recent'] = creation_ts
            
    except Exception as e:
        logger.debug(f"Warning: Failed to extract timestamps from certificate: {e}")
    
    return timestamps


def find_certificate_by_domain(local_cert_domains: List[str], namespace: str, tenant_name: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    """Find if a certificate with matching domains exists in F5XC by checking each certificate individually."""
    try:
        logger.info(f"Searching for certificates with domains {local_cert_domains} in namespace {namespace}")
        
        # Step 1: Get list of all certificate names in the namespace
        certificates_list = list_f5xc_certificates(namespace, tenant_name, session)
        logger.info(f"Found {len(certificates_list)} certificates in namespace {namespace}")
        
        if not certificates_list:
            logger.info("No certificates found in namespace")
            return None
        
        # Step 2: Check each certificate individually
        for cert_summary in certificates_list:
            cert_name = cert_summary.get('name', '')
            if not cert_name:
                continue
                
            logger.debug(f"Checking certificate: {cert_name}")
            
            try:
                # Step 3: Get detailed information for this specific certificate
                cert_details = get_f5xc_certificate_details(namespace, cert_name, tenant_name, session)
                
                if not cert_details:
                    logger.debug(f"  - No details found for {cert_name}")
                    continue
                
                # Step 4: Extract domains from this certificate
                cert_domains = extract_certificate_domains(cert_details)
                logger.debug(f"  - Certificate {cert_name} has domains: {cert_domains}")
                
                # Step 5: Check for domain matches (both exact and wildcard matching)
                domain_match_found = False
                matched_domains = []
                
                for local_domain in local_cert_domains:
                    for cert_domain in cert_domains:
                        # Direct match
                        if local_domain == cert_domain:
                            domain_match_found = True
                            matched_domains.append((local_domain, cert_domain, 'exact'))
                        # Wildcard match - check if local domain matches wildcard pattern
                        elif cert_domain.startswith('*.') and local_domain.endswith(cert_domain[1:]):
                            domain_match_found = True
                            matched_domains.append((local_domain, cert_domain, 'wildcard'))
                        # Reverse wildcard match - check if cert domain matches local wildcard
                        elif local_domain.startswith('*.') and cert_domain.endswith(local_domain[1:]):
                            domain_match_found = True
                            matched_domains.append((local_domain, cert_domain, 'reverse_wildcard'))
                
                if domain_match_found:
                    logger.debug(f"  - MATCH FOUND! Certificate {cert_name} matches with: {matched_domains}")
                    
                    # Extract timestamps
                    timestamps = extract_certificate_timestamps(cert_details)
                    
                    # Extract additional certificate information from spec.infos
                    cert_info = {}
                    spec = cert_details.get('spec', {})
                    infos = spec.get('infos', [])
                    if not infos:
                        # Fallback to get_spec.infos if spec.infos not found
                        get_spec = cert_details.get('get_spec', {})
                        infos = get_spec.get('infos', [])
                        
                    if infos:
                        info = infos[0]  # Take the first (and usually only) info entry
                        cert_info = {
                            'expiry': info.get('expiry'),
                            'issuer': info.get('issuer'),
                            'public_key_algorithm': info.get('public_key_algorithm'),
                            'organization': info.get('organization')
                        }
                    
                    return {
                        'name': cert_name,
                        'namespace': namespace,
                        'tenant': tenant_name,
                        'domains': cert_domains,
                        'matched_domains': matched_domains,
                        'details': cert_details,
                        'timestamps': timestamps,
                        'cert_info': cert_info,
                        'found_match': True
                    }
                else:
                    logger.debug(f"  - No domain match for {cert_name}")
                    
            except Exception as e:
                logger.debug(f"  - Error checking certificate {cert_name}: {e}")
                continue
        
        logger.info("No matching certificates found after checking all certificates")
        return None
        
    except Exception as e:
        logger.debug(f"Error in find_certificate_by_domain: {e}")
        raise Exception(f"Failed to find certificate by domain: {str(e)}")


def create_temp_config(cert_name: str, directory_name: str, custom_settings: Dict[str, Any] = None) -> str:
    """Create a temporary configuration file for F5XC operations."""
    import tempfile
    
    # Load base configuration
    try:
        with open(CONFIG_FILE, 'r') as f:
            base_config = json.load(f)
    except Exception:
        # Fallback configuration
        base_config = {
            "tenant_name": "volt-field",
            "namespace": "shared",
            "client_cert_path": str(Path(__file__).parent / "volt-field.p12"),
            "client_cert_password": "Redred99"
        }
    
    # Update configuration for the specific certificate
    config = base_config.copy()
    
    # Override with custom settings if provided
    if custom_settings:
        config.update(custom_settings)
    
    config['certificate_name'] = cert_name
    
    if directory_name:
        cert_dir = CERTS_DIR / directory_name
        config['fullchain_path'] = str(cert_dir / 'fullchain.pem')
        config['privkey_path'] = str(cert_dir / 'privkey.pem')
    
    # Create temporary config file
    temp_fd, temp_path = tempfile.mkstemp(suffix='.json', prefix='f5xc_config_')
    try:
        with os.fdopen(temp_fd, 'w') as f:
            json.dump(config, f, indent=2)
        return temp_path
    except Exception:
        os.unlink(temp_path)
        raise


@app.route('/api/tracking', methods=['GET'])
def get_tracking_data():
    """Get certificate tracking data."""
    try:
        tracking_data = load_certificate_tracking()
        return jsonify(tracking_data)
    except Exception as e:
        return jsonify({'error': f'Failed to load tracking data: {str(e)}'}), 500


@app.route('/api/tracking/certificate/<path:directory_name>', methods=['GET'])
def get_certificate_tracking(directory_name):
    """Get tracking data for a specific certificate directory."""
    try:
        deployments = get_certificate_deployments(directory_name)
        return jsonify({
            'directory_name': directory_name,
            'deployments': deployments
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get certificate tracking: {str(e)}'}), 500


@app.route('/api/tracking/clear', methods=['POST'])
def clear_tracking_data():
    """Clear all tracking data."""
    try:
        tracking_data = {
            'certificates': {},
            'history': [],
            'last_updated': datetime.now().isoformat()
        }
        save_certificate_tracking(tracking_data)
        return jsonify({'message': 'Tracking data cleared successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to clear tracking data: {str(e)}'}), 500


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current F5XC settings (without sensitive data)."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        # Return settings without sensitive information
        safe_config = {
            'tenant_name': config.get('tenant_name', ''),
            'namespace': config.get('namespace', ''),
            'client_cert_path': config.get('client_cert_path', ''),
            # Don't return the actual password, just indicate if one exists
            'has_password': bool(config.get('client_cert_password', ''))
        }
        return jsonify(safe_config)
    except Exception as e:
        # Return default settings if config file doesn't exist or is invalid
        return jsonify({
            'tenant_name': 'volt-field',
            'namespace': 'shared',
            'client_cert_path': str(Path(__file__).parent / "volt-field.p12"),
            'has_password': True
        })


@app.route('/api/settings', methods=['POST'])
def save_settings():
    """Save F5XC settings to config file."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No settings provided'}), 400
    
    try:
        # Load existing config or create new one
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except Exception:
            config = {}
        
        # Update with new settings
        if 'tenant_name' in data:
            config['tenant_name'] = data['tenant_name']
        if 'namespace' in data:
            config['namespace'] = data['namespace']
        if 'client_cert_path' in data:
            config['client_cert_path'] = data['client_cert_path']
        if 'client_cert_password' in data:
            config['client_cert_password'] = data['client_cert_password']
        
        # Save updated config
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        return jsonify({'message': 'Settings saved successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to save settings: {str(e)}'}), 500


@app.route('/api/settings/test', methods=['POST'])
def test_connection():
    """Test F5XC connection with provided settings."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No settings provided'}), 400
    
    # Create a temporary config for testing
    temp_config = create_temp_config('test-connection', '', data)
    
    try:
        manager = F5CertificateManager(temp_config)
        
        # Test by attempting to validate the config (this will check certificate files)
        try:
            manager._validate_config('delete')
            return jsonify({
                'success': True,
                'message': 'Connection test successful! Settings are valid.'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Connection test failed: {str(e)}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to test connection: {str(e)}'
        })
    finally:
        # Clean up temporary config file
        try:
            os.unlink(temp_config)
        except Exception:
            pass


@app.route('/api/validate/name', methods=['POST'])
def validate_certificate_name():
    """Validate a certificate name for F5XC compliance."""
    data = request.get_json()
    name = data.get('name', '')
    
    validation = validate_f5xc_name(name)
    return jsonify(validation)


@app.route('/api/f5xc/check', methods=['POST'])
def check_f5xc_certificate():
    """Check if a certificate exists in F5XC based on domain names."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        directory_name = data.get('directory_name')
        namespace = data.get('namespace')
        custom_settings = data.get('settings', {})
        
        # Input validation
        if not directory_name or not namespace:
            return jsonify({'error': 'Missing directory_name or namespace'}), 400
        
        # Validate directory name (path traversal protection)
        if not validate_input(directory_name, 255, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.'):
            return jsonify({'error': 'Invalid directory name'}), 400
            
        # Validate namespace
        if not validate_input(namespace, 64, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'):
            return jsonify({'error': 'Invalid namespace'}), 400
            
        logger.info(f"F5XC certificate check requested for {directory_name} in namespace {namespace}")
        
    except Exception as e:
        logger.error(f"Error parsing request: {e}")
        return jsonify({'error': 'Invalid request format'}), 400
    
    try:
        # Get the local certificate information first
        parser = CertificateParser()
        cert_dir = parser.certs_dir / directory_name
        
        if not cert_dir.exists():
            return jsonify({'error': 'Local certificate not found'}), 404
            
        fullchain_path = cert_dir / 'fullchain.pem'
        if not fullchain_path.exists():
            return jsonify({'error': 'Certificate file not found'}), 404
        
        # Parse local certificate to get domains
        cert_info = parser.parse_certificate(fullchain_path)
        if 'error' in cert_info:
            return jsonify({'error': f'Failed to parse local certificate: {cert_info["error"]}'}), 500
        
        # Get all domains (SAN + CN)
        local_domains = cert_info.get('san_domains', [])
        if cert_info.get('subject_common_name'):
            local_domains.append(cert_info['subject_common_name'])
        
        if not local_domains:
            return jsonify({'error': 'No domains found in local certificate'}), 400
        
        # Create temporary config for F5XC API access
        temp_config = create_temp_config('temp-check', directory_name, custom_settings)
        
        try:
            # Get F5XC session and config
            session, config = get_f5xc_session(temp_config)
            tenant_name = config.get('tenant_name')
            
            if not tenant_name:
                return jsonify({'error': 'Tenant name not configured'}), 400
            
            # Search for matching certificate in F5XC
            f5xc_cert = find_certificate_by_domain(local_domains, namespace, tenant_name, session)
            
            if f5xc_cert:
                # Update local tracking data with F5XC timestamps
                track_certificate_operation(
                    operation='found_existing',
                    cert_name=f5xc_cert['name'],
                    directory_name=directory_name,
                    namespace=namespace,
                    tenant=tenant_name,
                    success=True,
                    f5xc_timestamps=f5xc_cert.get('timestamps', {})
                )
                
                return jsonify({
                    'found': True,
                    'certificate': f5xc_cert,
                    'local_domains': local_domains,
                    'message': f'Certificate {f5xc_cert["name"]} found in F5XC namespace {namespace}'
                })
            else:
                return jsonify({
                    'found': False,
                    'local_domains': local_domains,
                    'message': f'No matching certificate found in F5XC namespace {namespace}'
                })
                
        finally:
            # Clean up temporary session files and config
            try:
                cleanup_f5xc_session(session)
            except Exception:
                pass
            try:
                os.unlink(temp_config)
            except Exception:
                pass
                
    except Exception as e:
        return jsonify({'error': f'Failed to check F5XC certificate: {str(e)}'}), 500


@app.route('/api/test/extract-domains', methods=['POST'])
def test_domain_extraction():
    """Test endpoint to verify domain extraction from F5XC certificate JSON."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No certificate data provided'}), 400
    
    try:
        domains = extract_certificate_domains(data)
        timestamps = extract_certificate_timestamps(data)
        
        # Extract additional info if available - try spec.infos first
        cert_info = {}
        spec = data.get('spec', {})
        infos = spec.get('infos', [])
        if not infos:
            # Fallback to get_spec.infos
            get_spec = data.get('get_spec', {})
            infos = get_spec.get('infos', [])
            
        if infos:
            info = infos[0]
            cert_info = {
                'expiry': info.get('expiry'),
                'issuer': info.get('issuer'),
                'public_key_algorithm': info.get('public_key_algorithm'),
                'organization': info.get('organization')
            }
        
        return jsonify({
            'domains': domains,
            'timestamps': timestamps,
            'cert_info': cert_info,
            'certificate_name': data.get('name'),
            'namespace': data.get('namespace'),
            'tenant': data.get('tenant')
        })
    except Exception as e:
        return jsonify({'error': f'Failed to extract data: {str(e)}'}), 500


@app.route('/api/debug/f5xc-list', methods=['POST'])
def debug_f5xc_list():
    """Debug endpoint to list all certificates in F5XC namespace and show detailed info."""
    data = request.get_json()
    namespace = data.get('namespace')
    custom_settings = data.get('settings', {})
    
    if not namespace:
        return jsonify({'error': 'Missing namespace'}), 400
    
    # Create temporary config for F5XC API access
    temp_config = create_temp_config('debug-list', '', custom_settings)
    
    try:
        # Get F5XC session and config
        session, config = get_f5xc_session(temp_config)
        tenant_name = config.get('tenant_name')
        
        if not tenant_name:
            return jsonify({'error': 'Tenant name not configured'}), 400
        
        # Get list of certificates
        certificates_list = list_f5xc_certificates(namespace, tenant_name, session)
        
        detailed_certs = []
        for cert_summary in certificates_list:
            cert_name = cert_summary.get('name', '')
            if cert_name:
                try:
                    # Get detailed certificate information
                    cert_details = get_f5xc_certificate_details(namespace, cert_name, tenant_name, session)
                    domains = extract_certificate_domains(cert_details)
                    timestamps = extract_certificate_timestamps(cert_details)
                    
                    detailed_certs.append({
                        'name': cert_name,
                        'domains': domains,
                        'timestamps': timestamps,
                        'summary': cert_summary
                    })
                except Exception as e:
                    detailed_certs.append({
                        'name': cert_name,
                        'error': str(e),
                        'summary': cert_summary
                    })
        
        return jsonify({
            'namespace': namespace,
            'tenant': tenant_name,
            'certificate_count': len(certificates_list),
            'certificates': detailed_certs
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to list F5XC certificates: {str(e)}'}), 500
    finally:
        # Clean up temporary session files and config
        try:
            cleanup_f5xc_session(session)
        except Exception:
            pass
        try:
            os.unlink(temp_config)
        except Exception:
            pass


@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files securely."""
    try:
        # Use safe_join to prevent directory traversal
        safe_path = safe_join(app.root_path, 'static')
        if not safe_path:
            logger.warning(f"Unsafe path attempt: {filename}")
            return jsonify({'error': 'File not found'}), 404
            
        return send_from_directory(safe_path, filename)
    except Exception as e:
        logger.error(f"Error serving static file {filename}: {e}")
        return jsonify({'error': 'File not found'}), 404


if __name__ == '__main__':
    # Production configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    if debug_mode:
        logger.warning("Running in debug mode - NOT suitable for production!")
    
    # Configure logging level based on environment
    if os.environ.get('FLASK_ENV') == 'production':
        app.logger.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    else:
        app.logger.setLevel(logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
    
    logger.info(f"Starting F5XC Certificate Manager on {host}:{port}")
    
    try:
        app.run(
            debug=debug_mode,
            host=host,
            port=port,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise