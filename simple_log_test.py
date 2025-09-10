#!/usr/bin/env python
"""
Simple test to verify logging works without Django
"""

import logging
import os
from pathlib import Path

# Create logs directory if it doesn't exist
logs_dir = Path('logs')
logs_dir.mkdir(exist_ok=True)

# Configure logging similar to Django settings
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/test.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('test_logger')

print("🧪 Testing Logging System...")
print(f"📁 Logs will be written to: {os.path.abspath('logs')}")

# Test basic logging
logger.info("This is a test log message")
logger.warning("This is a test warning")
logger.error("This is a test error")

# Check if log file was created
if os.path.exists('logs/test.log'):
    size = os.path.getsize('logs/test.log')
    print(f"✅ logs/test.log created ({size} bytes)")
    
    # Show log contents
    print("\n📄 Log file contents:")
    with open('logs/test.log', 'r') as f:
        print(f.read())
else:
    print("❌ logs/test.log not found")

print("\n🎉 Basic Logging Test Complete!")
