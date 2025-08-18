# Let's Encrypt Integration

This application now supports generating Let's Encrypt certificates using the `certbot-dns-multi` module, which provides access to 80+ DNS providers for domain validation.

## Features

- **Multi-DNS Provider Support**: Supports 80+ DNS providers via the `certbot-dns-multi` plugin
- **Web Interface**: User-friendly web interface for certificate generation
- **Domain Validation**: DNS-01 challenge for wildcard certificate support
- **Provider Configuration**: Dynamic form generation based on selected DNS provider
- **Staging Environment**: Support for Let's Encrypt staging environment for testing
- **Integration**: Generated certificates are automatically available for F5XC deployment

## Installation

### Prerequisites

1. Install required Python packages:
```bash
pip install -r requirements.txt
```

2. Install certbot and certbot-dns-multi:
```bash
# Option 1: Via pip
pip install certbot certbot-dns-multi

# Option 2: Via snap (recommended)
sudo snap install certbot-dns-multi
sudo snap set certbot trust-plugin-with-root=ok
sudo snap connect certbot:plugin certbot-dns-multi
```

### Verification

The application will automatically check if certbot and certbot-dns-multi are properly installed when you access the certificate generation feature.

## Usage

### Web Interface

1. **Start the Application**:
```bash
python3 app.py
```

2. **Access the Web Interface**:
   - Open http://localhost:5000 in your browser
   - Click the "Generate Certificate" button

3. **Generate a Certificate**:
   - **Step 1**: Enter your email and domain(s)
     - Email is required for Let's Encrypt registration
     - Enter one domain per line
     - Wildcard domains (*.example.com) are supported
   
   - **Step 2**: Select and configure your DNS provider
     - Load a saved configuration OR configure manually:
       - **Load Saved**: Select from previously saved configurations
       - **Manual**: Choose from 80+ supported providers and fill credentials
     - Use the "Validate Configuration" button to verify settings
     - **Save Configuration**: Save settings for future reuse
   
   - **Step 3**: Configure advanced options
     - Enable staging environment for testing
     - Force renewal if needed

4. **Certificate Generation**:
   - Click "Generate Certificate" to start the process
   - The certificate will be saved to the `certs/` directory
   - Certificate names follow F5XC conventions (main domain only)
   - Generated certificates appear in the main certificate list

### Supported DNS Providers

Popular providers include:
- **Cloudflare**: Global DNS provider with API access
- **Route53**: Amazon Web Services DNS
- **DigitalOcean**: DigitalOcean DNS service
- **GoDaddy**: Domain registrar and DNS
- **Namecheap**: Domain registrar and DNS
- **OVH**: European cloud and domain services

And 70+ more providers. See the full list at: https://go-acme.github.io/lego/dns/

### API Endpoints

The following REST API endpoints are available:

- `GET /api/letsencrypt/providers` - List supported DNS providers
- `GET /api/letsencrypt/check-installation` - Check certbot installation
- `GET /api/letsencrypt/provider/<provider>/requirements` - Get provider configuration requirements
- `POST /api/letsencrypt/generate` - Start asynchronous certificate generation (returns job ID)
- `GET /api/letsencrypt/job/<job_id>` - Check certificate generation job status
- `POST /api/letsencrypt/validate-config` - Validate DNS provider configuration
- `GET /api/letsencrypt/dns-configs` - List saved DNS provider configurations
- `POST /api/letsencrypt/dns-configs` - Save a new DNS provider configuration
- `GET /api/letsencrypt/dns-configs/<name>` - Get a specific saved configuration
- `DELETE /api/letsencrypt/dns-configs/<name>` - Delete a saved configuration

## Configuration Examples

### Cloudflare

**Required fields:**
- `CLOUDFLARE_DNS_API_TOKEN`: API token with Zone:Read and DNS:Edit permissions

**Alternative (less secure):**
- `CLOUDFLARE_EMAIL`: Account email
- `CLOUDFLARE_API_KEY`: Global API key

### Amazon Route53

**Required fields:**
- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key

**Optional:**
- `AWS_REGION`: AWS region (default: us-east-1)

### DigitalOcean

**Required fields:**
- `DO_AUTH_TOKEN`: DigitalOcean API token

## Security Considerations

1. **Credential Storage**: DNS provider credentials are only stored temporarily during certificate generation and are automatically cleaned up
2. **File Permissions**: Credential files are created with secure permissions (600)
3. **Staging Environment**: Use staging environment for testing to avoid rate limits
4. **Input Validation**: All inputs are validated for security
5. **Asynchronous Processing**: Certificate generation runs in background threads to prevent web server timeouts
6. **F5XC Naming Convention**: Certificate names use main domain only (e.g., `*.example.com` and `www.example.com` both create `example.com`)

## Performance & Reliability

### Asynchronous Processing
- **Non-blocking**: Certificate generation runs in background threads
- **Progress Tracking**: Real-time progress updates via job status API
- **Timeout Handling**: No web server timeouts during long-running operations
- **Job Persistence**: Job status is saved to disk for reliability

### Process Flow
1. User submits certificate generation request
2. System validates input and starts background job
3. Returns job ID immediately (fast response)
4. Frontend polls job status for progress updates
5. Job runs certbot in background (can take several minutes)
6. Final result is available via job status API

### Certificate Naming Convention

To ensure F5XC compatibility, certificate names automatically use the main domain:

| Input Domain(s) | Certificate Name | Directory |
|---|---|---|
| `*.stetsonneufeldduo.com` | `stetsonneufeldduo.com` | `certs/stetsonneufeldduo.com/` |
| `www.stetsonneufeldduo.com` | `stetsonneufeldduo.com` | `certs/stetsonneufeldduo.com/` |
| `api.stetsonneufeldduo.com` | `stetsonneufeldduo.com` | `certs/stetsonneufeldduo.com/` |
| `stetsonneufeldduo.com` | `stetsonneufeldduo.com` | `certs/stetsonneufeldduo.com/` |
| `www.example.com`, `api.example.com` | `example.com` | `certs/example.com/` |

This ensures consistent naming that complies with F5XC requirements and prevents conflicts.

## DNS Configuration Management

### Save and Reuse DNS Settings

The application allows you to save DNS provider configurations for easy reuse:

#### Saving a Configuration
1. Configure your DNS provider settings during certificate generation
2. Enter a configuration name (e.g., "My Cloudflare")
3. Add an optional description
4. Click "Save Configuration"
5. Settings are encrypted and stored locally

#### Loading a Saved Configuration
1. Open certificate generation modal
2. Select a configuration from the "Saved Configurations" dropdown
3. All DNS settings auto-populate instantly
4. Only need to enter domains and email for new certificates

#### Managing Configurations
- Click "Manage" button to view all saved configurations
- View creation dates and last used timestamps
- Delete unwanted configurations
- Use configurations directly from the management interface

#### Security Features
- Sensitive data (API keys, tokens) are base64 encoded for storage
- Configurations stored in local `dns_configs.json` file
- No sensitive data exposed in API listing endpoints
- Automatic cleanup on configuration deletion

#### Benefits
- **Time Saving**: No more re-entering credentials
- **Error Reduction**: Consistent, tested configurations
- **Multiple Providers**: Save configs for different DNS providers
- **Team Sharing**: Share configuration file between team members
- **Quick Switching**: Switch between production/staging configurations

## Troubleshooting

### Installation Issues

1. **Certbot not found**:
   ```bash
   # Install certbot
   pip install certbot
   # Or via system package manager
   sudo apt-get install certbot  # Ubuntu/Debian
   sudo yum install certbot      # CentOS/RHEL
   ```

2. **certbot-dns-multi not available**:
   ```bash
   # Install the plugin
   pip install certbot-dns-multi
   # Verify installation
   certbot plugins
   ```

### Certificate Generation Issues

1. **DNS Validation Failures**:
   - Verify DNS provider credentials are correct
   - Ensure API tokens have necessary permissions
   - Check domain ownership and DNS propagation

2. **Rate Limits**:
   - Use staging environment for testing
   - Let's Encrypt has rate limits: 50 certificates per registered domain per week

3. **Wildcard Certificates**:
   - Require DNS-01 challenge (automatically used)
   - Ensure your DNS provider supports API access

## Integration with F5XC

Generated Let's Encrypt certificates can be immediately deployed to F5 Distributed Cloud:

1. Generate certificate using the Let's Encrypt feature
2. Certificate appears in the main certificate list  
3. Use existing F5XC deployment features (Create/Replace) to deploy to F5XC
4. Configure F5XC settings in the Settings panel

### Smart Delete Functionality

The application includes intelligent delete logic based on F5XC deployment status:

#### Certificates with F5XC Deployments
- Shows F5XC delete dialog
- Attempts to delete from F5XC first
- Uses existing F5XC delete workflow

#### Certificates without F5XC Deployments  
- Shows local delete confirmation
- Deletes directly from local filesystem
- Skips F5XC API calls (prevents errors)
- Cleans up all certificate files:
  - `/certs/<certificate>/` directory
  - `/letsencrypt/config/live/<certificate>/` directory
  - `/letsencrypt/config/archive/<certificate>/` directory
  - `/letsencrypt/config/renewal/<certificate>.conf` file

## File Structure

```
f5xc/
├── letsencrypt_manager.py      # Let's Encrypt management module
├── app.py                      # Main Flask application (updated)
├── requirements.txt            # Python dependencies (updated)
├── templates/index.html        # Web interface (updated)
├── static/app.js              # Frontend JavaScript (updated)
├── test_letsencrypt.py        # Test script for functionality
├── test_dns_config_save.py    # DNS config save/load test
├── LETSENCRYPT_README.md      # This documentation
├── dns_configs.json           # Saved DNS provider configurations (encrypted)
├── letsencrypt/               # Let's Encrypt working directory
│   ├── config/               # Certbot configuration
│   ├── work/                 # Certbot working files
│   ├── logs/                 # Certbot logs
│   ├── jobs/                 # Job status tracking (JSON files)
│   └── dns-credentials/      # Temporary DNS credentials (auto-cleaned)
└── certs/                    # Generated certificates
    └── <domain>/
        ├── fullchain.pem
        ├── privkey.pem
        ├── cert.pem
        └── chain.pem
```

## Testing

Run the included test script to verify the integration:

```bash
python3 test_letsencrypt.py
```

This will test the LetsEncryptManager class and provide information about API endpoints.