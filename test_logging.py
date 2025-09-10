#!/usr/bin/env python
"""
Test script to verify logging system is working correctly
Run this to test if log files are created in the logs folder
"""

import os
import sys
import django

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')
django.setup()

from core.logging_utils import bank_logger
from django.contrib.auth.models import User

def test_logging_system():
    """Test the logging system"""
    print("🧪 Testing Logging System...")
    print(f"📁 Logs will be written to: {os.path.abspath('logs')}")
    
    # Test security logging
    print("\n1. Testing Security Logging...")
    bank_logger.log_security_event(
        'TEST_SECURITY_EVENT',
        None,
        {
            'test_data': 'This is a test security event',
            'ip_address': '127.0.0.1',
            'user_agent': 'Test Script'
        }
    )
    print("   ✅ Security event logged")
    
    # Test transaction logging  
    print("\n2. Testing Transaction Logging...")
    bank_logger.log_transaction_event(
        'TEST_TRANSACTION',
        None,  # No user for test
        {
            'test_data': 'This is a test transaction',
            'amount': '100.00',
            'account_id': 'test_account'
        },
        status='SUCCESS'
    )
    print("   ✅ Transaction event logged")
    
    # Test authentication logging
    print("\n3. Testing Authentication Logging...")
    bank_logger.log_authentication_attempt(
        'test_user',
        success=True,
        ip_address='127.0.0.1',
        details={'test': 'authentication test'}
    )
    print("   ✅ Authentication event logged")
    
    # Check if log files were created
    print("\n📂 Checking Log Files...")
    log_files = [
        'logs/django.log',
        'logs/security.log', 
        'logs/transactions.log',
        'logs/errors.log'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            size = os.path.getsize(log_file)
            print(f"   ✅ {log_file} created ({size} bytes)")
        else:
            print(f"   ❌ {log_file} not found")
    
    print("\n🎉 Logging System Test Complete!")
    print("\nTo view logs:")
    print("- Security events: tail -f logs/security.log")
    print("- Transactions: tail -f logs/transactions.log")
    print("- General logs: tail -f logs/django.log")
    print("- Errors: tail -f logs/errors.log")

if __name__ == "__main__":
    test_logging_system()
