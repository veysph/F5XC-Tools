#!/usr/bin/env python3
"""
Gunicorn configuration for F5XC Certificate Manager production deployment.
"""

import os
import multiprocessing

# Server socket
bind = f"{os.environ.get('FLASK_HOST', '127.0.0.1')}:{os.environ.get('FLASK_PORT', '5000')}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = 'sync'
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Logging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'f5xc-cert-manager'

# Preload application for better performance
preload_app = True

# Security headers
secure_headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
}

# Environment variables
raw_env = [
    f"FLASK_ENV={os.environ.get('FLASK_ENV', 'production')}",
]