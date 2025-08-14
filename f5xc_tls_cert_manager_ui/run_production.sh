#!/bin/bash
set -e

# F5XC Certificate Manager Production Startup Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting F5XC Certificate Manager in Production Mode${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root is not recommended for production${NC}"
fi

# Set default environment
export FLASK_ENV=production
export FLASK_DEBUG=false

# Load environment variables if .env exists
if [ -f ".env" ]; then
    echo -e "${GREEN}Loading environment variables from .env${NC}"
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check required directories exist
CERTS_DIR=${CERTS_DIR:-./certs}
CONFIG_FILE=${CONFIG_FILE:-./config.json}

echo -e "${GREEN}Checking configuration...${NC}"

if [ ! -d "$CERTS_DIR" ]; then
    echo -e "${YELLOW}Creating certificates directory: $CERTS_DIR${NC}"
    mkdir -p "$CERTS_DIR"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Configuration file not found: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}Please create a config.json file with your F5XC settings${NC}"
    exit 1
fi

# Check if gunicorn is available
if ! command -v gunicorn &> /dev/null; then
    echo -e "${RED}Error: gunicorn not found. Please install with: pip install gunicorn${NC}"
    exit 1
fi

# Start the application
echo -e "${GREEN}Starting application with gunicorn...${NC}"
echo -e "${YELLOW}Host: ${FLASK_HOST:-127.0.0.1}${NC}"
echo -e "${YELLOW}Port: ${FLASK_PORT:-5000}${NC}"
echo -e "${YELLOW}Workers: ${GUNICORN_WORKERS:-4}${NC}"

# Health check
echo -e "${GREEN}Application started successfully!${NC}"
echo -e "${YELLOW}Health check: http://${FLASK_HOST:-127.0.0.1}:${FLASK_PORT:-5000}${NC}"

# Start gunicorn
exec gunicorn --config gunicorn.conf.py app:app