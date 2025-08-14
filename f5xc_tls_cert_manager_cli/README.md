# F5 Distributed Cloud TLS Certificate Manager

A Python tool for managing TLS certificates on the F5 Distributed Cloud platform. This tool allows you to create, replace, and delete your own TLS certificates using the F5 Distributed Cloud API.

## Features

- ✅ Create, Replace/upgrade, Delete TLS certificates
- ✅ Dry-run mode for testing configurations

## Prerequisites

- Python 3.8 or higher
- F5 Distributed Cloud account
- F5 Distributed Client certificate for authentication, please see 
https://docs.cloud.f5.com/docs-v2/administration/how-tos/user-mgmt/Credentials#generate-api-certificate-for-my-credentials

## Setup Instructions

### 1. Create Python Virtual Environment

```bash
# Create a new virtual environment
python3 -m venv f5xc-cert-manager

# Activate the virtual environment
# On macOS/Linux:
source f5xc-cert-manager/bin/activate

# On Windows:
f5xc-cert-manager\Scripts\activate
```

### 2. Install Python Requirements

```bash
# Install required dependencies
pip install -r requirements.txt

# Or install manually:
pip install requests cryptography
```

### 3. Verify Installation

```bash
python f5xc_tls_cert_manager.py --help
```

## Configuration

### config.json Structure

Create a JSON configuration file with the following structure:

```json
{
  "tenant_name": "your-tenant-name",
  "namespace": "your-namespace",
  "certificate_name": "your-certificate-name",
  "client_cert_path": "/path/to/client-certificate.pem",
  "fullchain_path": "/path/to/fullchain.pem",
  "privkey_path": "/path/to/private-key.pem"
}
```

### Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant_name` | Yes | Your F5 Distributed Cloud tenant name |
| `namespace` | Yes | Target namespace for certificate operations |
| `certificate_name` | Yes | Name of the certificate to manage |
| `client_cert_path` | Yes | Path to client certificate for API authentication |
| `client_cert_password` | No | Password for P12/PFX client certificates |
| `fullchain_path` | Yes | Path to fullchain certificate file (create/replace only) |
| `privkey_path` | Yes | Path to private key file (create/replace only) |

### Example Configurations

#### Basic PEM Certificate Configuration

```json
{
  "tenant_name": "acme-corp",
  "namespace": "production",
  "certificate_name": "web-server-cert",
  "client_cert_path": "/certs/client.p12",
  "client_cert_password": "your-p12-password",
  "fullchain_path": "/certs/fullchain.pem",
  "privkey_path": "/certs/privkey.pem"
}
```

## Usage Examples

### Basic Operations

#### Create a New Certificate

```bash
python f5xc_tls_cert_manager.py --config config.json --create
```

#### Replace an Existing Certificate

```bash
python f5xc_tls_cert_manager.py --config config.json --replace
```

#### Delete a Certificate

```bash
python f5xc_tls_cert_manager.py --config config.json --delete
```

### Testing and Debugging

#### Dry Run (Test Configuration Without API Calls)

```bash
# Test create operation
python f5xc_tls_cert_manager.py --config config.json --create --dry-run

# Test replace operation
python f5xc_tls_cert_manager.py --config config.json --replace --dry-run

# Test delete operation
python f5xc_tls_cert_manager.py --config config.json --delete --dry-run
```

#### Enable Debug Mode

```bash
python f5xc_tls_cert_manager.py --config config.json --create --debug
```

### Command Line Options

```
Options:
  -h, --help            Show help message and exit
  -c CONFIG, --config CONFIG
                        Path to the JSON configuration file
  --create              Create a new certificate
  --replace             Replace/upgrade an existing certificate
  --delete              Delete an existing certificate
  --dry-run             Show what would be done without making API calls
  --debug               Enable debug mode with detailed output
```

### Certificate Chain Requirements

- **fullchain.pem**: Must contain the complete certificate chain including intermediate certificates
- **privkey.pem**: Must contain the private key corresponding to the certificate

### File Permissions

Ensure certificate files have appropriate permissions:

```bash
chmod 600 /path/to/private-key.pem
chmod 644 /path/to/fullchain.pem
chmod 600 /path/to/client-certificate.pem
```