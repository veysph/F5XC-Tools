#!/usr/bin/env python3
"""
Test script for Let's Encrypt functionality
"""

import json
from pathlib import Path
from letsencrypt_manager import LetsEncryptManager

def test_letsencrypt_manager():
    """Test the LetsEncryptManager class directly."""
    print("Testing LetsEncryptManager...")
    
    # Initialize manager
    base_dir = Path(__file__).parent
    manager = LetsEncryptManager(base_dir)
    
    # Test 1: Check supported providers
    print("\n1. Testing supported providers...")
    providers = manager.get_supported_providers()
    print(f"   Found {len(providers)} supported providers")
    print(f"   Sample providers: {providers[:10]}")
    
    # Test 2: Test provider requirements
    print("\n2. Testing provider requirements...")
    cloudflare_req = manager.get_provider_requirements('cloudflare')
    print(f"   Cloudflare requirements: {cloudflare_req['name']}")
    print(f"   Required fields: {len(cloudflare_req.get('required_fields', []))}")
    
    # Test 3: Test validation
    print("\n3. Testing DNS config validation...")
    
    # Valid Cloudflare config
    valid_config = {'CLOUDFLARE_DNS_API_TOKEN': 'test-token'}
    is_valid, error = manager.validate_provider_config('cloudflare', valid_config)
    print(f"   Valid config test: {is_valid} (expected: True)")
    
    # Invalid config
    invalid_config = {}
    is_valid, error = manager.validate_provider_config('cloudflare', invalid_config)
    print(f"   Invalid config test: {is_valid}, error: {error}")
    
    # Test 4: Check installation
    print("\n4. Testing installation check...")
    status = manager.check_certbot_installation()
    print(f"   Certbot installed: {status['certbot_installed']}")
    print(f"   DNS-multi available: {status['dns_multi_available']}")
    if status['certbot_version']:
        print(f"   Certbot version: {status['certbot_version']}")
    
    # Test 5: Test async job system
    print("\n5. Testing asynchronous job system...")
    
    # Test job start (this will fail due to no certbot, but tests the API)
    try:
        job_id = manager.start_certificate_generation(
            domains=['test.example.com'],
            provider='cloudflare',
            dns_config={'CLOUDFLARE_DNS_API_TOKEN': 'test-token'},
            email='test@example.com',
            staging=True
        )
        print(f"   Job started with ID: {job_id}")
        
        # Check job status
        import time
        time.sleep(1)  # Wait a moment
        job_status = manager.get_job_status(job_id)
        print(f"   Job status: {job_status.get('status', 'unknown')}")
        print(f"   Job progress: {job_status.get('progress', 'N/A')}")
        
    except Exception as e:
        print(f"   Async test error (expected): {e}")
    
    print("\nLetsEncryptManager tests completed!")

def test_api_endpoints():
    """Note about API endpoint testing."""
    print("\nAPI Endpoint Testing:")
    print("To test the Flask API endpoints, run the following:")
    print("1. python3 app.py")
    print("2. Visit http://localhost:5000 in your browser")
    print("3. Click 'Generate Certificate' button to test the Let's Encrypt functionality")
    print("\nAvailable API endpoints:")
    endpoints = [
        "GET /api/letsencrypt/providers",
        "GET /api/letsencrypt/check-installation", 
        "GET /api/letsencrypt/provider/<provider>/requirements",
        "POST /api/letsencrypt/generate (starts async job)",
        "GET /api/letsencrypt/job/<job_id> (check job status)",
        "POST /api/letsencrypt/validate-config"
    ]
    for endpoint in endpoints:
        print(f"   • {endpoint}")

if __name__ == "__main__":
    print("=" * 60)
    print("Let's Encrypt Integration Test")
    print("=" * 60)
    
    # Test the manager directly
    test_letsencrypt_manager()
    
    # Test API endpoints (requires Flask app running)
    test_api_endpoints()
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)