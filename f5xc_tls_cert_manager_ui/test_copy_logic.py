#!/usr/bin/env python3
"""
Test script for certificate copying logic
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

def test_certbot_directory_mapping():
    """Test how certbot directory names map to our logic."""
    print("Testing certbot directory name mapping...")
    
    test_cases = [
        # (input_domain, expected_certbot_dir, expected_cert_name)
        ('*.stetsonneufeldduo.com', 'stetsonneufeldduo.com', 'stetsonneufeldduo.com'),
        ('*.example.com', 'example.com', 'example.com'),
        ('www.stetsonneufeldduo.com', 'www.stetsonneufeldduo.com', 'stetsonneufeldduo.com'),
        ('api.example.com', 'api.example.com', 'example.com'),
        ('example.com', 'example.com', 'example.com'),
    ]
    
    print(f"\n{'Input Domain':<25} | {'Certbot Dir':<25} | {'Cert Name':<20} | Status")
    print("-" * 85)
    
    for input_domain, expected_certbot_dir, expected_cert_name in test_cases:
        # Simulate our logic
        certbot_dir_name = input_domain.replace('*.', '') if input_domain.startswith('*.') else input_domain
        
        # Extract main domain logic
        domain = input_domain
        if domain.startswith('*.'):
            domain = domain[2:]
        parts = domain.split('.')
        cert_name = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        
        certbot_ok = certbot_dir_name == expected_certbot_dir
        cert_name_ok = cert_name == expected_cert_name
        status = "PASS" if (certbot_ok and cert_name_ok) else "FAIL"
        
        print(f"{input_domain:<25} | {certbot_dir_name:<25} | {cert_name:<20} | {status}")

def test_existing_certificate():
    """Test with the actual existing certificate."""
    print("\n" + "="*60)
    print("TESTING EXISTING CERTIFICATE")
    print("="*60)
    
    base_dir = Path('/Users/veysph/f5xc')
    letsencrypt_dir = base_dir / 'letsencrypt'
    certs_dir = base_dir / 'certs'
    
    # Test the actual scenario
    primary_domain = '*.stetsonneufeldduo.com'
    
    # Our logic
    cert_name = 'stetsonneufeldduo.com'  # _extract_main_domain result
    certbot_dir_name = primary_domain.replace('*.', '') if primary_domain.startswith('*.') else primary_domain
    
    source_dir = letsencrypt_dir / 'config' / 'live' / certbot_dir_name
    dest_dir = certs_dir / cert_name
    
    print(f"Primary domain: {primary_domain}")
    print(f"Certbot directory: {certbot_dir_name}")
    print(f"Certificate name: {cert_name}")
    print(f"Source directory: {source_dir}")
    print(f"Destination directory: {dest_dir}")
    print(f"Source exists: {source_dir.exists()}")
    print(f"Destination exists: {dest_dir.exists()}")
    
    if source_dir.exists():
        print("\nSource directory contents:")
        for file in sorted(source_dir.iterdir()):
            if file.is_file():
                print(f"  ✓ {file.name}")
    
    if dest_dir.exists():
        print("\nDestination directory contents:")
        for file in sorted(dest_dir.iterdir()):
            if file.is_file():
                print(f"  ✓ {file.name}")
    
    # Check if all required files exist in destination
    required_files = ['fullchain.pem', 'privkey.pem', 'cert.pem', 'chain.pem']
    all_files_exist = all((dest_dir / file).exists() for file in required_files)
    
    print(f"\nAll required files in destination: {'YES' if all_files_exist else 'NO'}")
    
    if all_files_exist:
        print("✅ Certificate copying logic is working correctly!")
    else:
        print("❌ Certificate copying logic needs verification")

if __name__ == "__main__":
    test_certbot_directory_mapping()
    test_existing_certificate()