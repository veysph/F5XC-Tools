# F5XC Certificate Manager - Production Deployment Guide

## Prerequisites

- Python 3.9+
- F5 Distributed Cloud account and client certificate (.p12 file)
- SSL certificates to manage (Let's Encrypt format)

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

## Security Features

- **Content Security Policy**: Prevents XSS attacks
- **Security Headers**: HSTS, X-Frame-Options, etc.
- **Input Validation**: All user inputs are validated
- **Path Traversal Protection**: Safe file serving
- **Rate Limiting**: Built-in request limits
- **HTTPS Enforcement**: Security headers enforce HTTPS

## Monitoring

### Logs

```bash
# Application logs
sudo journalctl -u f5xc-cert-manager -f

# Gunicorn access logs
sudo journalctl -u f5xc-cert-manager -f | grep "GET\|POST"
```

### Health Check

```bash
curl -I http://localhost:5000/
```

Expected response: `200 OK`

## Backup

Important files to backup:
- `/opt/f5xc-cert-manager/config.json`
- `/opt/f5xc-cert-manager/certificate_tracking.json`
- `/opt/f5xc-cert-manager/certs/` (certificate directory)
- `/opt/f5xc-cert-manager/.env`

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo chown -R f5xc:f5xc /opt/f5xc-cert-manager
   ```

2. **Port Already in Use**
   ```bash
   sudo netstat -tulpn | grep :5000
   # Change FLASK_PORT in .env
   ```

3. **Certificate Path Issues**
   - Ensure absolute paths in config.json
   - Check file permissions for client certificate

4. **F5XC API Errors**
   - Verify client certificate is valid
   - Check network connectivity to F5XC
   - Validate tenant name and namespace

### Debug Mode

For troubleshooting, temporarily enable debug:

```bash
# Edit .env
FLASK_DEBUG=true
FLASK_ENV=development

# Restart service
sudo systemctl restart f5xc-cert-manager
```

**Warning**: Never run debug mode in production!

## Updates

```bash
# Stop service
sudo systemctl stop f5xc-cert-manager

# Update application files
sudo cp -r new-files/* /opt/f5xc-cert-manager/
sudo chown -R f5xc:f5xc /opt/f5xc-cert-manager

# Update dependencies
sudo -u f5xc ./venv/bin/pip install -r requirements.txt

# Start service
sudo systemctl start f5xc-cert-manager
```