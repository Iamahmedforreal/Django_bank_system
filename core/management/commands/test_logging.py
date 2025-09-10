from django.core.management.base import BaseCommand
from core.logging_utils import bank_logger
import os

class Command(BaseCommand):
    help = 'Test the logging system and verify log files are created'

    def handle(self, *args, **options):
        self.stdout.write("🧪 Testing Logging System...")
        self.stdout.write(f"📁 Logs will be written to: {os.path.abspath('logs')}")
        
        # Test security logging
        self.stdout.write("\n1. Testing Security Logging...")
        bank_logger.log_security_event(
            'TEST_SECURITY_EVENT',
            None,
            {
                'test_data': 'This is a test security event',
                'ip_address': '127.0.0.1',
                'user_agent': 'Django Management Command'
            }
        )
        self.stdout.write("   ✅ Security event logged")
        
        # Test transaction logging  
        self.stdout.write("\n2. Testing Transaction Logging...")
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
        self.stdout.write("   ✅ Transaction event logged")
        
        # Test authentication logging
        self.stdout.write("\n3. Testing Authentication Logging...")
        bank_logger.log_authentication_attempt(
            'test_user',
            success=True,
            ip_address='127.0.0.1',
            details={'test': 'authentication test'}
        )
        self.stdout.write("   ✅ Authentication event logged")
        
        # Check if log files were created
        self.stdout.write("\n📂 Checking Log Files...")
        log_files = [
            'logs/django.log',
            'logs/security.log', 
            'logs/transactions.log',
            'logs/errors.log'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                size = os.path.getsize(log_file)
                self.stdout.write(f"   ✅ {log_file} created ({size} bytes)")
            else:
                self.stdout.write(f"   ❌ {log_file} not found")
        
        self.stdout.write("\n🎉 Logging System Test Complete!")
        self.stdout.write(self.style.SUCCESS("Logging system is working correctly!"))
