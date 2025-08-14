# F5XC Certificate Manager - Production Deployment Guide

## Prerequisites

- Python 3.9+
- F5 Distributed Cloud account and client certificate (.p12 file)
- SSL certificates to manage

## Production Installation

### 1. System Setup

```bash
# Create application user
sudo useradd -r -s /bin/false f5xc

# Create application directory
sudo mkdir -p /opt/f5xc-cert-manager
sudo chown f5xc:f5xc /opt/f5xc-cert-manager
```

### 2. Application Setup

```bash
# Copy application files
sudo cp -r * /opt/f5xc-cert-manager/
sudo chown -R f5xc:f5xc /opt/f5xc-cert-manager

# Create virtual environment
cd /opt/f5xc-cert-manager
sudo -u f5xc python3 -m venv venv
sudo -u f5xc ./venv/bin/pip install -r requirements.txt
```

### 3. Configuration

```bash
# Copy environment template
sudo -u f5xc cp .env.example .env

# Edit configuration
sudo -u f5xc nano .env

# Set up F5XC configuration
sudo -u f5xc nano config.json
```

Example `config.json`:
```json
{
  "tenant_name": "your-tenant",
  "namespace": "shared",
  "client_cert_path": "/opt/f5xc-cert-manager/certs/client.p12",
  "client_cert_password": "your-password"
}
```

### 4. SSL/TLS Setup (Recommended)

For production, run behind a reverse proxy (nginx/Apache) with SSL:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 5. Systemd Service

```bash
# Install service file
sudo cp f5xc-cert-manager.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable f5xc-cert-manager
sudo systemctl start f5xc-cert-manager

# Check status
sudo systemctl status f5xc-cert-manager
```

## Manual Startup

For testing or development:

```bash
# Using the production script
./run_production.sh

# Or directly with gunicorn
gunicorn --config gunicorn.conf.py app:app
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `production` | Flask environment |
| `FLASK_DEBUG` | `false` | Debug mode |
| `FLASK_HOST` | `127.0.0.1` | Bind address |
| `FLASK_PORT` | `5000` | Port number |
| `SECRET_KEY` | Generated | Flask secret key |
| `CERTS_DIR` | `./certs` | Certificate directory |
| `CONFIG_FILE` | `./config.json` | Configuration file |
| `TRACKING_FILE` | `./certificate_tracking.json` | Tracking data file |
