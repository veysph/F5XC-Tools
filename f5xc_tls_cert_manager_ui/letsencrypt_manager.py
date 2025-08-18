#!/usr/bin/env python3
"""
Let's Encrypt Certificate Generation Manager

This module provides functionality to generate Let's Encrypt certificates
using certbot-dns-multi plugin with support for multiple DNS providers.
"""

import os
import json
import subprocess
import logging
import tempfile
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class LetsEncryptManager:
    """Manager for Let's Encrypt certificate generation using certbot-dns-multi."""
    
    def __init__(self, base_dir: Path = None):
        """Initialize the Let's Encrypt manager."""
        self.base_dir = base_dir or Path(__file__).parent
        self.letsencrypt_dir = self.base_dir / 'letsencrypt'
        self.certs_dir = self.base_dir / 'certs'
        self.dns_credentials_dir = self.letsencrypt_dir / 'dns-credentials'
        self.jobs_dir = self.letsencrypt_dir / 'jobs'
        
        # Job tracking
        self.active_jobs = {}  # job_id -> job_info
        
        # Ensure directories exist
        self.letsencrypt_dir.mkdir(exist_ok=True)
        self.certs_dir.mkdir(exist_ok=True)
        self.dns_credentials_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions for credentials
        self.jobs_dir.mkdir(exist_ok=True)
    
    def get_supported_providers(self) -> List[str]:
        """Get list of supported DNS providers from lego documentation."""
        return [
            'cloudflare', 'route53', 'digitalocean', 'godaddy', 'namecheap',
            'ovh', 'gandi', 'azure', 'googlecloud', 'linode', 'vultr',
            'acme-dns', 'alidns', 'autodns', 'bindman', 'bluecat',
            'brandit', 'checkdomain', 'civo', 'conoha', 'constellix',
            'derak', 'desec', 'designate', 'dnsimple', 'dnsmadeeasy',
            'dnspod', 'domeneshop', 'dreamhost', 'duckdns', 'dyn',
            'dynu', 'easydns', 'exec', 'exoscale', 'freemyip',
            'glesys', 'hostingde', 'hosttech', 'httpreq', 'huaweicloud',
            'hurricane', 'hyperone', 'inwx', 'ionos', 'joker',
            'lightsail', 'loopia', 'luadns', 'metaname', 'mythicbeasts',
            'namedotcom', 'nearlyfreespeech', 'netcup', 'netlify',
            'nicmanager', 'nodion', 'ns1', 'oraclecloud', 'otc',
            'pdns', 'plesk', 'porkbun', 'rackspace', 'rfc2136',
            'rimuhosting', 'sakuracloud', 'scaleway', 'selectel',
            'servercow', 'sonic', 'stackpath', 'tencentcloud',
            'transip', 'ultradns', 'vegadns', 'versio', 'vinyldns',
            'yandex', 'yandexcloud', 'zoneee', 'zonomi'
        ]
    
    def validate_provider_config(self, provider: str, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate DNS provider configuration."""
        if not provider or provider not in self.get_supported_providers():
            return False, f"Unsupported DNS provider: {provider}"
        
        # Common validation - ensure we have some configuration
        if not config:
            return False, "DNS provider configuration is required"
        
        # Provider-specific validation
        if provider == 'cloudflare':
            if not config.get('CLOUDFLARE_DNS_API_TOKEN') and not (config.get('CLOUDFLARE_EMAIL') and config.get('CLOUDFLARE_API_KEY')):
                return False, "Cloudflare requires either CLOUDFLARE_DNS_API_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY"
        
        elif provider == 'route53':
            if not config.get('AWS_ACCESS_KEY_ID') or not config.get('AWS_SECRET_ACCESS_KEY'):
                return False, "Route53 requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
        
        elif provider == 'digitalocean':
            if not config.get('DO_AUTH_TOKEN'):
                return False, "DigitalOcean requires DO_AUTH_TOKEN"
        
        elif provider == 'godaddy':
            if not config.get('GODADDY_API_KEY') or not config.get('GODADDY_API_SECRET'):
                return False, "GoDaddy requires GODADDY_API_KEY and GODADDY_API_SECRET"
        
        elif provider == 'namecheap':
            if not config.get('NAMECHEAP_API_USER') or not config.get('NAMECHEAP_API_KEY'):
                return False, "Namecheap requires NAMECHEAP_API_USER and NAMECHEAP_API_KEY"
        
        elif provider == 'ovh':
            required_fields = ['OVH_ENDPOINT', 'OVH_APPLICATION_KEY', 'OVH_APPLICATION_SECRET', 'OVH_CONSUMER_KEY']
            missing = [field for field in required_fields if not config.get(field)]
            if missing:
                return False, f"OVH requires: {', '.join(missing)}"
        
        return True, None
    
    def create_dns_credentials_file(self, provider: str, config: Dict[str, Any]) -> Path:
        """Create DNS credentials file for certbot-dns-multi."""
        # Validate configuration first
        is_valid, error_msg = self.validate_provider_config(provider, config)
        if not is_valid:
            raise ValueError(error_msg)
        
        # Create credentials file
        creds_file = self.dns_credentials_dir / f"{provider}-credentials.ini"
        
        # Start with the provider name
        creds_content = [f"dns_multi_provider = {provider}"]
        
        # Add all configuration variables
        for key, value in config.items():
            if key and value:
                creds_content.append(f"{key} = {value}")
        
        # Write credentials file with secure permissions
        creds_file.write_text('\n'.join(creds_content))
        creds_file.chmod(0o600)  # Read/write for owner only
        
        logger.info(f"Created DNS credentials file: {creds_file}")
        return creds_file
    
    def start_certificate_generation(self, domains: List[str], provider: str, dns_config: Dict[str, Any], 
                                    email: str, staging: bool = False, force_renewal: bool = False) -> str:
        """Start asynchronous certificate generation and return job ID."""
        if not domains:
            raise ValueError("At least one domain is required")
        
        if not email:
            raise ValueError("Email address is required for Let's Encrypt registration")
        
        # Validate domains
        for domain in domains:
            if not self._validate_domain(domain):
                raise ValueError(f"Invalid domain name: {domain}")
        
        # Create unique job ID
        job_id = str(uuid.uuid4())
        
        # Create job info
        job_info = {
            'id': job_id,
            'status': 'starting',
            'domains': domains,
            'provider': provider,
            'email': email,
            'staging': staging,
            'force_renewal': force_renewal,
            'created_at': datetime.now().isoformat(),
            'progress': 'Initializing certificate generation...',
            'result': None
        }
        
        # Store job info
        self.active_jobs[job_id] = job_info
        self._save_job_status(job_id, job_info)
        
        # Start background thread
        thread = threading.Thread(
            target=self._generate_certificate_async,
            args=(job_id, domains, provider, dns_config, email, staging, force_renewal),
            daemon=True
        )
        thread.start()
        
        return job_id
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get the status of a certificate generation job."""
        # First check memory
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]
        
        # Then check disk
        job_file = self.jobs_dir / f"{job_id}.json"
        if job_file.exists():
            try:
                with open(job_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error reading job file {job_file}: {e}")
        
        return {'error': f'Job {job_id} not found'}
    
    def _save_job_status(self, job_id: str, job_info: Dict[str, Any]):
        """Save job status to disk."""
        try:
            job_file = self.jobs_dir / f"{job_id}.json"
            with open(job_file, 'w') as f:
                json.dump(job_info, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving job status: {e}")
    
    def _generate_certificate_async(self, job_id: str, domains: List[str], provider: str, 
                                   dns_config: Dict[str, Any], email: str, staging: bool, 
                                   force_renewal: bool):
        """Generate certificate asynchronously in background thread."""
        job_info = self.active_jobs[job_id]
        
        try:
            # Update status
            job_info['status'] = 'validating'
            job_info['progress'] = 'Validating configuration...'
            self._save_job_status(job_id, job_info)
            
            # Validate provider configuration
            is_valid, error_msg = self.validate_provider_config(provider, dns_config)
            if not is_valid:
                raise ValueError(error_msg)
            
            # Create DNS credentials file
            job_info['progress'] = 'Creating DNS credentials...'
            self._save_job_status(job_id, job_info)
            
            creds_file = self.create_dns_credentials_file(provider, dns_config)
            
            try:
                # Prepare certbot command
                job_info['status'] = 'running'
                job_info['progress'] = 'Running certbot certificate generation...'
                self._save_job_status(job_id, job_info)
                
                cmd = [
                    'certbot', 'certonly',
                    '--authenticator', 'dns-multi',
                    '--dns-multi-credentials', str(creds_file),
                    '--email', email,
                    '--agree-tos',
                    '--non-interactive',
                    '--config-dir', str(self.letsencrypt_dir / 'config'),
                    '--work-dir', str(self.letsencrypt_dir / 'work'),
                    '--logs-dir', str(self.letsencrypt_dir / 'logs'),
                ]
                
                # Add staging flag if requested
                if staging:
                    cmd.append('--staging')
                
                # Add force renewal if requested
                if force_renewal:
                    cmd.append('--force-renewal')
                
                # Add domains
                for domain in domains:
                    cmd.extend(['-d', domain])
                
                logger.info(f"Running certbot command: {' '.join(cmd)}")
                
                # Execute certbot (no timeout in background)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    # Success - copy certificates to our certs directory
                    job_info['progress'] = 'Copying certificate files...'
                    self._save_job_status(job_id, job_info)
                    
                    primary_domain = domains[0]
                    # Extract main domain for F5XC compatibility (e.g., *.example.com -> example.com, www.example.com -> example.com)
                    cert_name = self._extract_main_domain(primary_domain)
                    
                    # Certbot saves wildcard certificates without the *. prefix, so we need to use the actual directory name
                    certbot_dir_name = primary_domain.replace('*.', '') if primary_domain.startswith('*.') else primary_domain
                    source_dir = self.letsencrypt_dir / 'config' / 'live' / certbot_dir_name
                    dest_dir = self.certs_dir / cert_name
                    
                    if source_dir.exists():
                        # Create destination directory
                        dest_dir.mkdir(exist_ok=True)
                        
                        # Copy certificate files
                        shutil.copy2(source_dir / 'fullchain.pem', dest_dir / 'fullchain.pem')
                        shutil.copy2(source_dir / 'privkey.pem', dest_dir / 'privkey.pem')
                        shutil.copy2(source_dir / 'cert.pem', dest_dir / 'cert.pem')
                        shutil.copy2(source_dir / 'chain.pem', dest_dir / 'chain.pem')
                        
                        logger.info(f"Certificate generated and saved to: {dest_dir}")
                        
                        result_data = {
                            'success': True,
                            'certificate_name': cert_name,
                            'domains': domains,
                            'cert_directory': str(dest_dir),
                            'fullchain_path': str(dest_dir / 'fullchain.pem'),
                            'privkey_path': str(dest_dir / 'privkey.pem'),
                            'provider': provider,
                            'staging': staging,
                            'generated_at': datetime.now().isoformat(),
                            'stdout': result.stdout,
                            'stderr': result.stderr
                        }
                        
                        job_info['status'] = 'completed'
                        job_info['progress'] = 'Certificate generated successfully!'
                        job_info['result'] = result_data
                        
                    else:
                        result_data = {
                            'success': False,
                            'error': f"Certificate directory not found: {source_dir}",
                            'stdout': result.stdout,
                            'stderr': result.stderr
                        }
                        
                        job_info['status'] = 'failed'
                        job_info['progress'] = 'Certificate directory not found'
                        job_info['result'] = result_data
                else:
                    result_data = {
                        'success': False,
                        'error': f"Certbot failed with exit code {result.returncode}",
                        'stdout': result.stdout,
                        'stderr': result.stderr
                    }
                    
                    job_info['status'] = 'failed'
                    job_info['progress'] = f'Certbot failed with exit code {result.returncode}'
                    job_info['result'] = result_data
                
            finally:
                # Clean up credentials file
                try:
                    creds_file.unlink()
                    logger.info(f"Cleaned up credentials file: {creds_file}")
                except Exception as e:
                    logger.warning(f"Failed to clean up credentials file: {e}")
        
        except Exception as e:
            logger.error(f"Error in certificate generation job {job_id}: {e}")
            result_data = {
                'success': False,
                'error': f"Unexpected error during certificate generation: {str(e)}"
            }
            
            job_info['status'] = 'failed'
            job_info['progress'] = f'Error: {str(e)}'
            job_info['result'] = result_data
        
        finally:
            # Update final status
            job_info['completed_at'] = datetime.now().isoformat()
            self.active_jobs[job_id] = job_info
            self._save_job_status(job_id, job_info)
    
    def generate_certificate(self, domains: List[str], provider: str, dns_config: Dict[str, Any], 
                           email: str, staging: bool = False, force_renewal: bool = False) -> Dict[str, Any]:
        """Generate certificate synchronously (for backward compatibility)."""
        job_id = self.start_certificate_generation(domains, provider, dns_config, email, staging, force_renewal)
        
        # Poll for completion
        while True:
            job_info = self.get_job_status(job_id)
            if job_info.get('status') in ['completed', 'failed']:
                return job_info.get('result', {'success': False, 'error': 'Unknown error'})
            
            time.sleep(1)  # Wait 1 second before checking again
    
    def _extract_main_domain(self, domain: str) -> str:
        """Extract the main domain from any domain (wildcard, subdomain, etc.)."""
        # Remove wildcard prefix if present
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Split domain into parts
        parts = domain.split('.')
        
        # If domain has more than 2 parts, extract the last 2 parts (main domain)
        # Examples: 
        # - www.example.com -> example.com
        # - sub.example.com -> example.com  
        # - api.v1.example.com -> example.com
        # - example.com -> example.com
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        # If domain has only 1 part or is invalid, return as-is
        return domain
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        import re
        
        if not domain or len(domain) > 253:
            return False
        
        # Allow wildcard domains
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Basic domain validation regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return re.match(domain_pattern, domain) is not None
    
    def check_certbot_installation(self) -> Dict[str, Any]:
        """Check if certbot and certbot-dns-multi are installed."""
        try:
            # Check certbot
            certbot_result = subprocess.run(['certbot', '--version'], capture_output=True, text=True)
            certbot_installed = certbot_result.returncode == 0
            certbot_version = certbot_result.stdout.strip() if certbot_installed else None
            
            # Check certbot-dns-multi plugin
            plugin_result = subprocess.run(['certbot', 'plugins'], capture_output=True, text=True)
            dns_multi_available = 'dns-multi' in plugin_result.stdout if plugin_result.returncode == 0 else False
            
            return {
                'certbot_installed': certbot_installed,
                'certbot_version': certbot_version,
                'dns_multi_available': dns_multi_available,
                'plugins_output': plugin_result.stdout if plugin_result.returncode == 0 else None
            }
        except FileNotFoundError:
            return {
                'certbot_installed': False,
                'certbot_version': None,
                'dns_multi_available': False,
                'plugins_output': None
            }
    
    def get_provider_requirements(self, provider: str) -> Dict[str, Any]:
        """Get configuration requirements for a specific DNS provider."""
        provider_configs = {
            'cloudflare': {
                'name': 'Cloudflare',
                'description': 'Global DNS provider with API access',
                'required_fields': [
                    {
                        'name': 'CLOUDFLARE_DNS_API_TOKEN',
                        'description': 'API token with Zone:Read and DNS:Edit permissions (recommended)',
                        'type': 'password',
                        'required': False
                    }
                ],
                'alternative_fields': [
                    {
                        'name': 'CLOUDFLARE_EMAIL',
                        'description': 'Email address associated with Cloudflare account',
                        'type': 'email',
                        'required': True
                    },
                    {
                        'name': 'CLOUDFLARE_API_KEY',
                        'description': 'Global API key (less secure alternative)',
                        'type': 'password',
                        'required': True
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/cloudflare/'
            },
            'route53': {
                'name': 'Amazon Route53',
                'description': 'AWS DNS service',
                'required_fields': [
                    {
                        'name': 'AWS_ACCESS_KEY_ID',
                        'description': 'AWS access key ID',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'name': 'AWS_SECRET_ACCESS_KEY',
                        'description': 'AWS secret access key',
                        'type': 'password',
                        'required': True
                    }
                ],
                'optional_fields': [
                    {
                        'name': 'AWS_REGION',
                        'description': 'AWS region (default: us-east-1)',
                        'type': 'text',
                        'required': False
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/route53/'
            },
            'digitalocean': {
                'name': 'DigitalOcean',
                'description': 'DigitalOcean DNS service',
                'required_fields': [
                    {
                        'name': 'DO_AUTH_TOKEN',
                        'description': 'DigitalOcean API token',
                        'type': 'password',
                        'required': True
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/digitalocean/'
            },
            'godaddy': {
                'name': 'GoDaddy',
                'description': 'GoDaddy domain registrar and DNS',
                'required_fields': [
                    {
                        'name': 'GODADDY_API_KEY',
                        'description': 'GoDaddy API key',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'name': 'GODADDY_API_SECRET',
                        'description': 'GoDaddy API secret',
                        'type': 'password',
                        'required': True
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/godaddy/'
            },
            'namecheap': {
                'name': 'Namecheap',
                'description': 'Namecheap domain registrar and DNS',
                'required_fields': [
                    {
                        'name': 'NAMECHEAP_API_USER',
                        'description': 'Namecheap API username',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'name': 'NAMECHEAP_API_KEY',
                        'description': 'Namecheap API key',
                        'type': 'password',
                        'required': True
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/namecheap/'
            },
            'ovh': {
                'name': 'OVH',
                'description': 'OVH cloud and domain services',
                'required_fields': [
                    {
                        'name': 'OVH_ENDPOINT',
                        'description': 'OVH API endpoint (e.g., ovh-eu)',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'name': 'OVH_APPLICATION_KEY',
                        'description': 'OVH application key',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'name': 'OVH_APPLICATION_SECRET',
                        'description': 'OVH application secret',
                        'type': 'password',
                        'required': True
                    },
                    {
                        'name': 'OVH_CONSUMER_KEY',
                        'description': 'OVH consumer key',
                        'type': 'password',
                        'required': True
                    }
                ],
                'docs_url': 'https://go-acme.github.io/lego/dns/ovh/'
            }
        }
        
        return provider_configs.get(provider, {
            'name': provider.title(),
            'description': f'{provider.title()} DNS provider',
            'required_fields': [],
            'docs_url': f'https://go-acme.github.io/lego/dns/{provider}/'
        })
    
    def list_existing_certificates(self) -> List[Dict[str, Any]]:
        """List existing certificates in the certs directory."""
        certificates = []
        
        if not self.certs_dir.exists():
            return certificates
        
        for cert_dir in self.certs_dir.iterdir():
            if cert_dir.is_dir():
                fullchain_path = cert_dir / 'fullchain.pem'
                privkey_path = cert_dir / 'privkey.pem'
                
                if fullchain_path.exists():
                    cert_info = {
                        'name': cert_dir.name,
                        'directory': str(cert_dir),
                        'fullchain_path': str(fullchain_path),
                        'privkey_path': str(privkey_path) if privkey_path.exists() else None,
                        'has_private_key': privkey_path.exists(),
                        'created_at': datetime.fromtimestamp(fullchain_path.stat().st_mtime).isoformat()
                    }
                    certificates.append(cert_info)
        
        return sorted(certificates, key=lambda x: x['created_at'], reverse=True)