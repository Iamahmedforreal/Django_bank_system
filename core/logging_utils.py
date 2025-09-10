"""
Logging utilities for the Bank Management System
Provides structured logging for security, transactions, and audit events
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from django.contrib.auth.models import User
from .models import Account, Transaction


class BankLogger:
    """Centralized logging utility for banking operations"""
    
    def __init__(self):
        self.security_logger = logging.getLogger('core.security')
        self.transaction_logger = logging.getLogger('core.transactions')
        self.general_logger = logging.getLogger('core.views')
    
    def log_security_event(self, event_type: str, user: Optional[User], 
                          details: Dict[str, Any], severity: str = 'INFO'):
        """Log security-related events"""
        log_data = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'user_id': user.id if user else None,
            'username': user.username if user else 'anonymous',
            'severity': severity,
            'details': details
        }
        
        message = f"SECURITY_EVENT: {json.dumps(log_data)}"
        
        if severity == 'ERROR':
            self.security_logger.error(message)
        elif severity == 'WARNING':
            self.security_logger.warning(message)
        else:
            self.security_logger.info(message)
    
    def log_transaction_event(self, event_type: str, user: User, 
                            transaction_data: Dict[str, Any], 
                            status: str = 'SUCCESS'):
        """Log transaction-related events"""
        log_data = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'user_id': user.id if user else None,
            'username': user.username if user else 'anonymous',
            'status': status,
            'transaction_data': transaction_data
        }
        
        message = f"TRANSACTION_EVENT: {json.dumps(log_data)}"
        
        if status == 'FAILED':
            self.transaction_logger.error(message)
        else:
            self.transaction_logger.info(message)
    
    def log_authentication_attempt(self, username: str, success: bool, 
                                 ip_address: str = None, details: Dict = None):
        """Log authentication attempts"""
        self.log_security_event(
            'AUTHENTICATION_ATTEMPT',
            None,
            {
                'username': username,
                'success': success,
                'ip_address': ip_address,
                'details': details or {}
            },
            severity='WARNING' if not success else 'INFO'
        )
    
    def log_authorization_failure(self, user: User, resource: str, 
                                action: str, details: Dict = None):
        """Log authorization failures"""
        self.log_security_event(
            'AUTHORIZATION_FAILURE',
            user,
            {
                'resource': resource,
                'action': action,
                'details': details or {}
            },
            severity='WARNING'
        )
    
    def log_transfer_attempt(self, user: User, source_account_id: int, 
                           recipient_iban: str, amount: str, success: bool,
                           error_message: str = None):
        """Log money transfer attempts"""
        self.log_transaction_event(
            'MONEY_TRANSFER',
            user,
            {
                'source_account_id': source_account_id,
                'recipient_iban': recipient_iban,
                'amount': amount,
                'error_message': error_message
            },
            status='SUCCESS' if success else 'FAILED'
        )
    
    def log_account_access(self, user: User, account_id: int, action: str):
        """Log account access attempts"""
        self.log_security_event(
            'ACCOUNT_ACCESS',
            user,
            {
                'account_id': account_id,
                'action': action
            }
        )
    
    def log_deposit_withdrawal(self, user: User, account_id: int, 
                             operation: str, amount: str, success: bool):
        """Log deposit and withdrawal operations"""
        self.log_transaction_event(
            f'{operation.upper()}_OPERATION',
            user,
            {
                'account_id': account_id,
                'amount': amount
            },
            status='SUCCESS' if success else 'FAILED'
        )
    
    def log_daily_limit_exceeded(self, user: User, account_id: int, 
                               attempted_amount: str, current_total: str,
                               daily_limit: str):
        """Log when daily transfer limits are exceeded"""
        self.log_security_event(
            'DAILY_LIMIT_EXCEEDED',
            user,
            {
                'account_id': account_id,
                'attempted_amount': attempted_amount,
                'current_daily_total': current_total,
                'daily_limit': daily_limit
            },
            severity='WARNING'
        )
    
    def log_suspicious_activity(self, user: User, activity_type: str, 
                              details: Dict[str, Any]):
        """Log potentially suspicious activities"""
        self.log_security_event(
            'SUSPICIOUS_ACTIVITY',
            user,
            {
                'activity_type': activity_type,
                'details': details
            },
            severity='WARNING'
        )


# Global logger instance
bank_logger = BankLogger()


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_api_request(request, endpoint: str, user: Optional[User] = None):
    """Log API request details"""
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'method': request.method,
        'endpoint': endpoint,
        'user_id': user.id if user else None,
        'username': user.username if user else 'anonymous',
        'ip_address': get_client_ip(request),
        'user_agent': request.META.get('HTTP_USER_AGENT', '')
    }
    
    logger = logging.getLogger('core.views')
    logger.info(f"API_REQUEST: {json.dumps(log_data)}")


def log_model_change(user: User, model_name: str, object_id: int, 
                    action: str, changes: Dict = None):
    """Log model changes for audit trail"""
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'user_id': user.id,
        'username': user.username,
        'model': model_name,
        'object_id': object_id,
        'action': action,  # CREATE, UPDATE, DELETE
        'changes': changes or {}
    }
    
    logger = logging.getLogger('core.transactions')
    logger.info(f"MODEL_CHANGE: {json.dumps(log_data)}")
