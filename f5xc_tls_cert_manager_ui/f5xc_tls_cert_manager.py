#!/usr/bin/env python3
"""
F5 Distributed Cloud TLS Certificate Manager

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
from pathlib import Path
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


class F5CertificateManager:
    def __init__(self, config_file: str):
        """Initialize the certificate manager with a config file."""
        self.config = self._load_config(config_file)
        self.temp_files = []

    def _load_config(self, config_file: str) -> Dict[Any, Any]:
        """Load and parse the JSON configuration file."""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            print(f"✓ Configuration loaded from {config_file}")
            return config
        except FileNotFoundError:
            print(f"✗ Error: Configuration file '{config_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Error: Invalid JSON in configuration file: {e}")
            sys.exit(1)

    def _validate_config(self, operation: str):
        """Validate the required configuration parameters based on operation."""
        # Common required fields for all operations
        common_fields = ['tenant_name', 'namespace', 'certificate_name', 'client_cert_path']

        # Additional fields required for create and replace operations
        cert_fields = ['fullchain_path', 'privkey_path']

        if operation in ['create', 'replace']:
            required_fields = common_fields + cert_fields
        else:  # delete operation
            required_fields = common_fields

        missing_fields = [field for field in required_fields if field not in self.config]
        if missing_fields:
            fields_str = ', '.join(missing_fields)
            print(f"✗ Error: Missing required configuration fields: {fields_str}")
            sys.exit(1)

        # Check if certificate files exist (only for create and replace operations)
        if operation in ['create', 'replace']:
            cert_files = [
                ('fullchain_path', self.config['fullchain_path']),
                ('privkey_path', self.config['privkey_path']),
                ('client_cert_path', self.config['client_cert_path'])
            ]

            for field_name, file_path in cert_files:
                if not Path(file_path).exists():
                    print(f"✗ Error: Certificate file '{file_path}' ({field_name}) not found")
                    sys.exit(1)
        else:
            # For delete operation, only check client certificate
            if not Path(self.config['client_cert_path']).exists():
                print(f"✗ Error: Client certificate file '{self.config['client_cert_path']}' not found")
                sys.exit(1)

        print(f"✓ Configuration validation completed for {operation} operation")

    def _encode_certificate_file(self, file_path: str) -> str:
        """Read a certificate file and encode it as base64."""
        try:
            with open(file_path, 'rb') as f:
                cert_content = f.read()
            encoded = base64.b64encode(cert_content).decode('utf-8')
            print(f"✓ Encoded certificate file: {file_path}")
            return encoded
        except Exception as e:
            print(f"✗ Error reading certificate file '{file_path}': {e}")
            sys.exit(1)

    def _create_payload(self, operation: str) -> Dict[str, Any]:
        """Create the JSON payload for the API request."""
        if operation == 'delete':
            # For delete operation, create simple payload
            payload = {
                "namespace": self.config['namespace'],
                "name": self.config['certificate_name']
            }
            print("✓ Delete payload created successfully")
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

        print(f"✓ Payload created successfully")
        return payload

    def _extract_p12_certificate(self, p12_path: str, password: str = None) -> Tuple[str, str]:
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

            print(f"✓ Extracted P12 certificate to temporary PEM files")
            return cert_path, key_path

        except Exception as e:
            print(f"✗ Error extracting P12 certificate: {e}")
            sys.exit(1)

    def _get_client_cert_info(self):
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
                print(f"✓ Cleaned up temporary file: {temp_file}")
            except Exception as e:
                print(f"⚠ Warning: Could not clean up temporary file {temp_file}: {e}")

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
            # Create payload
            payload = self._create_payload(operation)

            # Prepare request based on operation
            if operation == 'delete':
                url = f"https://{self.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{self.config['namespace']}/certificates/{self.config['certificate_name']}"
                method = 'DELETE'
            elif operation == 'replace':
                url = f"https://{self.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{self.config['namespace']}/certificates/{self.config['certificate_name']}"
                method = 'PUT'
            else:  # create
                url = f"https://{self.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{self.config['namespace']}/certificates"
                method = 'POST'

            headers = {
                'Content-Type': 'application/json'
            }

            # Handle client certificate authentication
            client_cert_info = self._get_client_cert_info()

            print(f"🚀 {operation.capitalize()} certificate '{self.config['certificate_name']}' on F5 Distributed Cloud...")
            print(f"   Tenant: {self.config['tenant_name']}")
            print(f"   Namespace: {self.config['namespace']}")
            print(f"   Method: {method}")
            print(f"   URL: {url}")

            # Make the API request
            if operation == 'delete':
                response = requests.delete(
                    url=url,
                    json=payload,
                    headers=headers,
                    cert=client_cert_info,
                    timeout=30
                )
            elif operation == 'replace':
                response = requests.put(
                    url=url,
                    json=payload,
                    headers=headers,
                    cert=client_cert_info,
                    timeout=30
                )
            else:  # create
                response = requests.post(
                    url=url,
                    json=payload,
                    headers=headers,
                    cert=client_cert_info,
                    timeout=30
                )

            # Handle response
            success_codes = [200, 201, 204] if operation != 'delete' else [200, 201, 204, 404]

            if response.status_code in success_codes:
                if operation == 'delete' and response.status_code == 404:
                    print(f"✅ Certificate '{self.config['certificate_name']}' was already deleted or doesn't exist")
                else:
                    print(f"✅ Certificate {operation}d successfully!")

                print(f"   Response: {response.status_code}")
                if response.text:
                    try:
                        response_data = response.json()
                        print(f"   Details: {json.dumps(response_data, indent=2)}")
                    except:
                        print(f"   Response text: {response.text}")
                return True
            else:
                print(f"❌ Failed to {operation} certificate")
                print(f"   Status code: {response.status_code}")
                print(f"   Response: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False
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

    print("🔧 F5 Distributed Cloud TLS Certificate Manager")
    print("=" * 52)

    # Determine operation
    if args.create:
        operation = 'create'
    elif args.replace:
        operation = 'replace'
    else:
        operation = 'delete'

    # Initialize the certificate manager
    manager = F5CertificateManager(args.config)
    manager._validate_config(operation)

    if args.dry_run:
        print(f"🔍 DRY RUN MODE - No actual API calls will be made for {operation} operation")
        payload = manager._create_payload(operation)
        print(f"\nPayload that would be sent for {operation}:")
        print(json.dumps(payload, indent=2))

        if operation == 'delete':
            url = f"https://{manager.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{manager.config['namespace']}/certificates/{manager.config['certificate_name']}"
            method = "DELETE"
        elif operation == 'replace':
            url = f"https://{self.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{self.config['namespace']}/certificates/{self.config['certificate_name']}"
            method = "PUT"
        else:  # create
            url = f"https://{manager.config['tenant_name']}.console.ves.volterra.io/api/config/namespaces/{manager.config['namespace']}/certificates"
            method = "POST"

        print(f"\nMethod: {method}")
        print(f"URL: {url}")
    else:
        # Execute the operation
        if operation == 'create':
            operation_value = "creation"
            success = manager.create_certificate()
        elif operation == 'replace':
            operation_value = "replacement"
            success = manager.replace_certificate()
        else:  # delete
            operation_value = "deletion"
            success = manager.delete_certificate()

        if success:
            print(f"\n🎉 Certificate {operation_value} completed successfully!")
            sys.exit(0)
        else:
            print(f"\n💥 Certificate {operation_value} failed!")
            sys.exit(1)


if __name__ == "__main__":
    main()
