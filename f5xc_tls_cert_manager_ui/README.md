# F5 Distributed Cloud TLS Certificate Manager

## Purpose

This web application provides a user-friendly interface for managing TLS certificates on the F5 Distributed Cloud platform. It allows users to view certificate details, monitor expiration dates, and perform create, replace, and delete operations through a small web interface.



**Key Features:**
- Local certificates discovery and status monitoring
- Visual expiration alerts and status indicators
- F5 Distributed Cloud integration (create, replace, delete certificates)

**Let's Encrypt Integration**
- Generate Let's Encrypt certificates for any domain using 80+ DNS providers

**Certbot multi DNS Configuration Management**
- Save DNS provider configurations for reuse
- Load saved configurations with one click
- Manage configurations (view, delete)
- Encrypted storage of sensitive data

## Required Directory Structure (Runtime)

After deployment, you'll need to create these additional directories and files:

```
your-deployment-location/
├── [all files from this package]
├── config.json                  # Your actual F5XC configuration
├── your-client-cert.p12         # F5 Distributed Cloud client certificate
├── certs/                       # Let's Encrypt certificates directory
│   ├── domain1.com/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   ├── domain2.com/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   └── ...
└── certificate_tracking.json    # Auto-created tracking file
```

## Quick Start Installation

### 1. Prerequisites

- Python
- F5 Distributed Cloud account and client certificate (.p12 file)
- TLS certificates in the expected directory structure
- Network access to Let's Encrypt servers
- DNS provider API access configured

### 2. Basic Setup

```bash
# Extract deployment package
cd /path/to/your/deployment/location

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

```bash
# Create configuration from template
cp config.json.example config.json

# Edit configuration with your F5XC details
nano config.json
```

**Example config.json:**
```json
{
  "tenant_name": "your-f5xc-tenant",
  "namespace": "shared",
  "client_cert_path": "your-client-cert.p12",
  "client_cert_password": "your-cert-password"
}
```

### 4. Certificate Directory Setup

```bash
# Create certificates directory
mkdir -p certs

# Add your Let's Encrypt certificates
# Each domain should have its own subdirectory with fullchain.pem and privkey.pem
mkdir certs/example.com
cp /path/to/your/fullchain.pem certs/example.com/
cp /path/to/your/privkey.pem certs/example.com/
```

### 5. Run the Application

**Development/Testing:**
```bash
# Simple development server
python app.py

# Access at: http://127.0.0.1:5000
```

**Production:**
```bash
# Using the provided production script
chmod +x run_production.sh
./run_production.sh

# Or directly with gunicorn
gunicorn --config gunicorn.conf.py app:app
```

## Production Deployment

For production deployment with systemd service, SSL/TLS termination, and security hardening, see the detailed **DEPLOYMENT.md** guide included in this package.

## Files
**Core Application Files**
- `app.py` - Main Flask application with all API endpoints
- `letsencrypt_manager.py` - Let's Encrypt certificate generation module
- `requirements.txt` - Updated Python dependencies
- `templates/index.html` - Updated HTML template with Let's Encrypt UI
- `static/app.js` - Updated JavaScript with certificate generation functionality
- `static/style.css` - Updated CSS styles

**Production Files**
- `f5xc_tls_cert_manager.py` - Production service wrapper
- `gunicorn.conf.py` - Gunicorn configuration
- `run_production.sh` - Production startup script
- `f5xc-cert-manager.service` - Systemd service file
- `config.json.example` - Configuration example
