from django.db import models
import random

class Customer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    
    
class Account(models.Model):
    account_number = models.CharField(max_length=20, unique=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    ACCOUNT_TYPE = [('savings', 'Savings')
                    , ('checking', 'Checking')]
    balance = models.DecimalField(max_digits=12,  decimal_places=2 , default=0.00)

    account_type = models.CharField(max_length=20 , choices=ACCOUNT_TYPE)
    created_at = models.DateTimeField(auto_now_add=True)

    def save (self, *args, **kwargs):
        if not self.account_number:
            self.account_number = str(random.randint(1000000000, 9999999999))
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
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.transaction_type} of {self.amount}"
    


    