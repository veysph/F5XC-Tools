#!/usr/bin/env python3
"""
Test script specifically for wildcard domain validation
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from letsencrypt_manager import LetsEncryptManager

def test_wildcard_validation():
    """Test wildcard domain validation."""
    print("Testing wildcard domain validation...")
    
    manager = LetsEncryptManager()
    
    test_cases = [
        # (domain, expected_result, description)
        ('*.stetsonneufeldduo.com', True, 'Valid wildcard domain'),
        ('*.example.com', True, 'Valid wildcard domain'),
        ('*.sub.example.com', True, 'Valid wildcard subdomain'),
        ('stetsonneufeldduo.com', True, 'Valid regular domain'),
        ('www.stetsonneufeldduo.com', True, 'Valid subdomain'),
        ('*.', False, 'Invalid - wildcard with no domain'),
        ('*', False, 'Invalid - wildcard only'),
        ('*.invalid..domain', False, 'Invalid - double dots'),
        ('*.-example.com', False, 'Invalid - starts with hyphen'),
        ('*.example-.com', False, 'Invalid - ends with hyphen'),
    ]
    
    print("\nDomain validation tests:")
    all_passed = True
    
    for domain, expected, description in test_cases:
        try:
            result = manager._validate_domain(domain)
            status = "PASS" if result == expected else "FAIL"
            if result != expected:
                all_passed = False
            print(f"  {domain:<25} | {status:<4} | {description}")
        except Exception as e:
            print(f"  {domain:<25} | ERROR | {e}")
            all_passed = False
    
    print(f"\nOverall result: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    # Test Flask input validation
    print("\nFlask input validation test:")
    allowed_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.*'
    
    def validate_input(data: str, max_length: int = 1000, allowed_chars: str = None) -> bool:
        if not data or len(data) > max_length:
            return False
        if allowed_chars:
            return all(c in allowed_chars for c in data)
        return True
    
    flask_test_domains = ['*.stetsonneufeldduo.com', '*.example.com', 'regular.domain.com']
    
    for domain in flask_test_domains:
        result = validate_input(domain, 253, allowed_chars)
        print(f"  {domain:<25} | {'PASS' if result else 'FAIL'} | Flask input validation")

if __name__ == "__main__":
    test_wildcard_validation()