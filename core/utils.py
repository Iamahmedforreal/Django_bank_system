import random
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

def generate_random_otp():
    """Generate a random 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_sms_otp(phone_number, otp):
    """Send OTP via Twilio SMS or mock for testing."""
    try:
        # Check if we're in mock mode for testing
        mock_mode = getattr(settings, 'MOCK_SMS', True)
        
        if mock_mode:
            # Mock SMS sending for testing
            logger.info(f"MOCK SMS: Sending OTP {otp} to {phone_number}")
            logger.info(f"MOCK SMS: OTP sent successfully to {phone_number[-4:]}****")
            return f"mock_message_sid_{otp}"
        
        # Real Twilio SMS sending
        try:
            from twilio.rest import Client
        except ImportError:
            logger.error("Twilio package not installed. Install with: pip install twilio")
            return None
            
        account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
        auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
        from_number = getattr(settings, 'TWILIO_PHONE_NUMBER', None)
        
        if not all([account_sid, auth_token, from_number]):
            logger.error("Twilio credentials not configured properly")
            return None
            
        client = Client(account_sid, auth_token)
        
        message = client.messages.create(
            body=f"Your Banking OTP is: {otp}. Valid for 5 minutes. Do not share this code.",
            from_=from_number,
            to=phone_number
        )
        
        logger.info(f"Real SMS: OTP sent successfully to {phone_number[-4:]}****")
        return message.sid
        
    except Exception as e:
        logger.error(f"Failed to send OTP: {str(e)}")
        return None

def is_otp_valid(customer):
    """Check if customer's OTP is still valid (within 5 minutes)."""
    if not customer.otp_created_at:
        return False
    
    expiry_time = customer.otp_created_at + timedelta(minutes=5)
    return timezone.now() <= expiry_time

def verify_otp(customer, provided_otp):
    """Verify if provided OTP matches and is still valid."""
    if not customer.two_factor_otp or not customer.otp_created_at:
        return False
    
    # Check if OTP is expired
    if not is_otp_valid(customer):
        return False
    
    # Check if OTP matches
    return customer.two_factor_otp == provided_otp