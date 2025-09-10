from django.db import models
from django.contrib.auth.models import User
import random

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    phone_number = models.CharField(max_length=15, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_otp = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    
    
class Account(models.Model):
    account_number = models.CharField(max_length=20, unique=True)
    iban = models.CharField(max_length=34, unique=True, null=True, blank=True)  # International Bank Account Number
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    ACCOUNT_TYPE = [('savings', 'Savings')
                    , ('checking', 'Checking')]
    balance = models.DecimalField(max_digits=12,  decimal_places=2 , default=0.00)

    account_type = models.CharField(max_length=20 , choices=ACCOUNT_TYPE)
    created_at = models.DateTimeField(auto_now_add=True)

    def save (self, *args, **kwargs):
        if not self.account_number:
            self.account_number = str(random.randint(1000000000, 9999999999))
        
        # Auto-generate IBAN if not provided (simplified format for demo)
        if not self.iban:
            # Format: US + 2 check digits + 4 bank code + 10 account number
            bank_code = "BANK"
            check_digits = str(random.randint(10, 99))
            self.iban = f"US{check_digits}{bank_code}{self.account_number}"
        
        super().save(*args, **kwargs)
        

    def __str__(self):
        return f"Account {self.account_number} {self.customer}"
    
class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('transfer', 'Transfer'),
    ]

    account = models.ForeignKey(Account, on_delete=models.CASCADE , related_name='transactions') 
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.transaction_type} of {self.amount}"
    


    