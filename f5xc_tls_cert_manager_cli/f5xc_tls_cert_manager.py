#!/usr/bin/env python3
"""
F5 Distributed Cloud TLS Certificate Manager - Optimized Version

This script creates, replaces, and deletes TLS certificates on F5 Distributed Cloud platform using
a JSON configuration file and certificate files.
"""

import json
import base64
import requests
import argparse
import sys
import tempfile
import os
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


# Constants
API_BASE_URL = "https://{tenant}.console.ves.volterra.io/api/config"
NAMESPACE_CERTS_ENDPOINT = "/namespaces/{namespace}/certificates"
CERT_ENDPOINT = "/namespaces/{namespace}/certificates/{cert_name}"
DEFAULT_TIMEOUT = 30
SUCCESS_CODES = [200, 201, 204]
DELETE_SUCCESS_CODES = [200, 201, 204, 404]
CHUNK_SIZE = 8192

# Operation mappings
OPERATION_METHODS = {
    'create': 'POST',
    'replace': 'PUT',
    'delete': 'DELETE'
}

OPERATION_ENDPOINTS = {
    'create': NAMESPACE_CERTS_ENDPOINT,
    'replace': CERT_ENDPOINT,
    'delete': CERT_ENDPOINT
}


class CertificateManagerError(Exception):
    """Base exception for certificate manager errors."""
    pass


class ConfigurationError(CertificateManagerError):
    """Raised when configuration is invalid."""
    pass


class CertificateFileError(CertificateManagerError):
    """Raised when certificate file operations fail."""
    pass


class APIError(CertificateManagerError):
    """Raised when API operations fail."""
    pass


class F5CertificateManager:
    def __init__(self, config_file: str):
        """Initialize the certificate manager with a config file."""
        self._setup_logging()
        self.config = self._load_config(config_file)
        self.temp_files = []
        self.logger = logging.getLogger(self.__class__.__name__)

    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(levelname)s: %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load and parse the JSON configuration file."""
        logger = logging.getLogger(self.__class__.__name__)
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            logger.info(f"✓ Configuration loaded from {config_file}")
            return config
        except FileNotFoundError:
            logger.error(f"✗ Error: Configuration file '{config_file}' not found")
            raise ConfigurationError(f"Configuration file '{config_file}' not found")
        except json.JSONDecodeError as e:
            logger.error(f"✗ Error: Invalid JSON in configuration file: {e}")
            raise ConfigurationError(f"Invalid JSON in configuration file: {e}")

    def _validate_config(self, operation: str):
        """Validate the required configuration parameters based on operation."""
        common_fields = ['tenant_name', 'namespace', 'certificate_name', 'client_cert_path']
        cert_fields = ['fullchain_path', 'privkey_path']

        if operation in ['create', 'replace']:
            required_fields = common_fields + cert_fields
        else:  # delete operation
            required_fields = common_fields

        missing_fields = [field for field in required_fields if field not in self.config]
        if missing_fields:
            fields_str = ', '.join(missing_fields)
            error_msg = f"Missing required configuration fields: {fields_str}"
            self.logger.error(f"✗ Error: {error_msg}")
            raise ConfigurationError(error_msg)

        # Check if certificate files exist
        if operation in ['create', 'replace']:
            cert_files = [
                ('fullchain_path', self.config['fullchain_path']),
                ('privkey_path', self.config['privkey_path']),
                ('client_cert_path', self.config['client_cert_path'])
            ]

            for field_name, file_path in cert_files:
                if not Path(file_path).exists():
                    error_msg = f"Certificate file '{file_path}' ({field_name}) not found"
                    self.logger.error(f"✗ Error: {error_msg}")
                    raise CertificateFileError(error_msg)
        else:
            # For delete operation, only check client certificate
            if not Path(self.config['client_cert_path']).exists():
                error_msg = f"Client certificate file '{self.config['client_cert_path']}' not found"
                self.logger.error(f"✗ Error: {error_msg}")
                raise CertificateFileError(error_msg)

        self.logger.info(f"✓ Configuration validation completed for {operation} operation")

    def _encode_certificate_file(self, file_path: str) -> str:
        """Read a certificate file and encode it as base64 with streaming for large files."""
        try:
            file_size = Path(file_path).stat().st_size

            # For small files, read directly
            if file_size < CHUNK_SIZE * 10:
                with open(file_path, 'rb') as f:
                    cert_content = f.read()
            else:
                # For larger files, read in chunks
                cert_content = b''
                with open(file_path, 'rb') as f:
                    while chunk := f.read(CHUNK_SIZE):
                        cert_content += chunk

            encoded = base64.b64encode(cert_content).decode('utf-8')
            self.logger.info(f"✓ Encoded certificate file: {file_path}")
            return encoded
        except (OSError, IOError) as e:
            error_msg = f"Error reading certificate file '{file_path}': {e}"
            self.logger.error(f"✗ {error_msg}")
            raise CertificateFileError(error_msg)

    def _build_api_url(self, operation: str) -> str:
        """Build API URL for the given operation."""
        base_url = API_BASE_URL.format(tenant=self.config['tenant_name'])
        endpoint = OPERATION_ENDPOINTS[operation].format(
            namespace=self.config['namespace'],
            cert_name=self.config['certificate_name']
        )
        return base_url + endpoint

    def _create_payload(self, operation: str) -> Dict[str, Any]:
        """Create the JSON payload for the API request."""
        if operation == 'delete':
            payload = {
                "namespace": self.config['namespace'],
                "name": self.config['certificate_name']
            }
            self.logger.info("✓ Delete payload created successfully")
            return payload

        # For create and replace operations, encode certificate files
        fullchain_b64 = self._encode_certificate_file(self.config['fullchain_path'])
        privkey_b64 = self._encode_certificate_file(self.config['privkey_path'])

        # Create the metadata
        metadata = {
            "name": self.config['certificate_name'],
            "namespace": self.config['namespace']
        }

        # Add description for replace operation
        if operation == 'replace':
            metadata["description"] = "replace"

        # Create the payload structure
        payload = {
            "metadata": metadata,
            "spec": {
                "certificate_url": f"string:///{fullchain_b64}",
                "private_key": {
                    "clear_secret_info": {
                        "url": f"string:///{privkey_b64}"
                    }
                }
            }
        }

        self.logger.info("✓ Payload created successfully")
        return payload

    def _extract_p12_certificate(self, p12_path: str, password: Optional[str] = None) -> Tuple[str, str]:
        """Extract certificate and private key from P12 file and create temporary PEM files."""
        try:
            # Read P12 file
            with open(p12_path, 'rb') as f:
                p12_data = f.read()

            # Convert password to bytes if provided
            password_bytes = password.encode('utf-8') if password else None

            # Load P12 certificate
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, password_bytes
            )

            # Create temporary files for certificate and key
            cert_fd, cert_path = tempfile.mkstemp(suffix='.pem', prefix='f5_cert_')
            key_fd, key_path = tempfile.mkstemp(suffix='.pem', prefix='f5_key_')

            # Store paths for cleanup
            self.temp_files.extend([cert_path, key_path])

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

            self.logger.info("✓ Extracted P12 certificate to temporary PEM files")
            return cert_path, key_path

        except Exception as e:
            error_msg = f"Error extracting P12 certificate: {e}"
            self.logger.error(f"✗ {error_msg}")
            raise CertificateFileError(error_msg)

    def _get_client_cert_info(self) -> Union[str, Tuple[str, str]]:
        """Get client certificate information for authentication."""
        client_cert_path = self.config['client_cert_path']

        # Check if it's a P12 file
        if client_cert_path.lower().endswith(('.p12', '.pfx')):
            password = self.config.get('client_cert_password', '')
            cert_path, key_path = self._extract_p12_certificate(client_cert_path, password)
            return (cert_path, key_path)
        else:
            # If password is provided in config, use it
            if 'client_cert_password' in self.config and self.config['client_cert_password']:
                return (client_cert_path, self.config['client_cert_password'])
            else:
                return client_cert_path

    def _cleanup_temp_files(self):
        """Clean up temporary files."""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
                self.logger.info(f"✓ Cleaned up temporary file: {temp_file}")
            except OSError as e:
                self.logger.warning(f"⚠ Warning: Could not clean up temporary file {temp_file}: {e}")

    def _make_api_request(self, operation: str, url: str, payload: Dict[str, Any], 
                         client_cert_info: Union[str, Tuple[str, str]]) -> requests.Response:
        """Make unified API request based on operation type."""
        headers = {'Content-Type': 'application/json'}
        method = OPERATION_METHODS[operation]

        request_kwargs = {
            'url': url,
            'headers': headers,
            'cert': client_cert_info,
            'timeout': DEFAULT_TIMEOUT
        }

        if operation != 'delete':
            request_kwargs['json'] = payload
        else:
            request_kwargs['json'] = payload

        self.logger.info(f"🚀 {operation.capitalize()} certificate '{self.config['certificate_name']}' on F5 Distributed Cloud...")
        self.logger.info(f"   Tenant: {self.config['tenant_name']}")
        self.logger.info(f"   Namespace: {self.config['namespace']}")
        self.logger.info(f"   Method: {method}")
        self.logger.info(f"   URL: {url}")

        return requests.request(method, **request_kwargs)

    def _handle_response(self, response: requests.Response, operation: str) -> bool:
        """Handle API response with proper error checking."""
        success_codes = DELETE_SUCCESS_CODES if operation == 'delete' else SUCCESS_CODES

        if response.status_code in success_codes:
            if operation == 'delete' and response.status_code == 404:
                self.logger.info(f"✅ Certificate '{self.config['certificate_name']}' was already deleted or doesn't exist")
            else:
                self.logger.info(f"✅ Certificate {operation}d successfully!")

            self.logger.info(f"   Response: {response.status_code}")
            if response.text:
                try:
                    response_data = response.json()
                    self.logger.info(f"   Details: {json.dumps(response_data, indent=2)}")
                except json.JSONDecodeError:
                    self.logger.info(f"   Response text: {response.text}")
            return True
        else:
            self.logger.error(f"❌ Failed to {operation} certificate")
            self.logger.error(f"   Status code: {response.status_code}")
            self.logger.error(f"   Response: {response.text}")
            return False

    def create_certificate(self) -> bool:
        """Create a new certificate on F5 Distributed Cloud platform."""
        return self._execute_operation('create')

    def replace_certificate(self) -> bool:
        """Replace/upgrade an existing certificate on F5 Distributed Cloud platform."""
        return self._execute_operation('replace')

    def delete_certificate(self) -> bool:
        """Delete a certificate from F5 Distributed Cloud platform."""
        return self._execute_operation('delete')

    def _execute_operation(self, operation: str) -> bool:
        """Execute the specified operation (create, replace, or delete)."""
        try:
            # Validate configuration
            self._validate_config(operation)

            # Create payload and URL
            payload = self._create_payload(operation)
            url = self._build_api_url(operation)

            # Handle client certificate authentication
            client_cert_info = self._get_client_cert_info()

            # Make API request
            response = self._make_api_request(operation, url, payload, client_cert_info)

            # Handle response
            return self._handle_response(response, operation)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"❌ Network error: {e}")
            raise APIError(f"Network error: {e}")
        except (ConfigurationError, CertificateFileError, APIError):
            return False
        except Exception as e:
            self.logger.error(f"❌ Unexpected error: {e}")
            raise APIError(f"Unexpected error: {e}")
        finally:
            # Clean up temporary files
            self._cleanup_temp_files()


def main():
    """Main function to handle command line arguments and execute the script."""
    parser = argparse.ArgumentParser(
        description='Manage TLS certificates on F5 Distributed Cloud platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example usage:
  # Create a new certificate
  python f5_cert_manager.py --config config.json --create

  # Replace/upgrade an existing certificate 
  python f5_cert_manager.py --config config.json --replace

  # Delete a certificate
  python f5_cert_manager.py --config config.json --delete

  # Test operations without making actual API calls
  python f5_cert_manager.py --config config.json --create --dry-run
  python f5_cert_manager.py --config config.json --replace --dry-run
  python f5_cert_manager.py --config config.json --delete --dry-run
        '''
    )

    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to the JSON configuration file'
    )

    # Operation arguments (mutually exclusive)
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        '--create',
        action='store_true',
        help='Create a new certificate'
    )
    operation_group.add_argument(
        '--replace',
        action='store_true',
        help='Replace/upgrade an existing certificate'
    )
    operation_group.add_argument(
        '--delete',
        action='store_true',
        help='Delete an existing certificate'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making the actual API call'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with detailed output'
    )

    args = parser.parse_args()

    # Setup logging level based on debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.info("🔧 F5 Distributed Cloud TLS Certificate Manager")
    logger.info("=" * 52)

    # Determine operation using dictionary lookup
    operation_map = {
        'create': args.create,
        'replace': args.replace,
        'delete': args.delete
    }
    operation = next(op for op, selected in operation_map.items() if selected)

    try:
        # Initialize the certificate manager
        manager = F5CertificateManager(args.config)

        if args.dry_run:
            logger.info(f"🔍 DRY RUN MODE - No actual API calls will be made for {operation} operation")
            payload = manager._create_payload(operation)
            logger.info(f"\nPayload that would be sent for {operation}:")
            logger.info(json.dumps(payload, indent=2))

            url = manager._build_api_url(operation)
            method = OPERATION_METHODS[operation]

            logger.info(f"\nMethod: {method}")
            logger.info(f"URL: {url}")
        else:
            # Execute the operation
            operation_methods = {
                'create': manager.create_certificate,
                'replace': manager.replace_certificate,
                'delete': manager.delete_certificate
            }

            operation_values = {
                'create': 'creation',
                'replace': 'replacement',
                'delete': 'deletion'
            }

            success = operation_methods[operation]()

            if success:
                logger.info(f"\n🎉 Certificate {operation_values[operation]} completed successfully!")
                sys.exit(0)
            else:
                logger.error(f"\n💥 Certificate {operation_values[operation]} failed!")
                sys.exit(1)

    except (ConfigurationError, CertificateFileError, APIError) as e:
        logger.error(f"💥 {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()