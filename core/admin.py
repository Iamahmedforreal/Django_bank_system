from django.contrib import admin
from .models import Customer, Account, Transaction

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('id', 'first_name', 'last_name', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('first_name', 'last_name')

@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ('account_number', 'customer', 'account_type', 'balance', 'created_at')
    list_filter = ('account_type', 'created_at')
    search_fields = ('account_number', 'customer__first_name', 'customer__last_name')

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('account', 'transaction_type', 'amount', 'created_at')
    list_filter = ('transaction_type', 'created_at')
    search_fields = ('account__account_number', 'account__customer__first_name', 'account__customer__last_name')



    
