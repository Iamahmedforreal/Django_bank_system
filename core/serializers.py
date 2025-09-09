from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db import transaction
from decimal import Decimal
from .models import Customer, Account, Transaction


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 'first_name', 'last_name')

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            Customer.objects.create(
                user=user,
                first_name=first_name,
                last_name=last_name
            )
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include username and password')


class CustomerSerializer(serializers.ModelSerializer):
    """Serializer for Customer model"""
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = Customer
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'created_at')
        read_only_fields = ('id', 'created_at')


class AccountSerializer(serializers.ModelSerializer):
    """Serializer for Account model"""
    customer_name = serializers.CharField(source='customer.user.username', read_only=True)
    
    class Meta:
        model = Account
        fields = ('id', 'account_number', 'customer', 'customer_name', 'account_type', 'balance', 'created_at')
        read_only_fields = ('id', 'account_number', 'balance', 'created_at')

    def create(self, validated_data):
        # Set the customer to the authenticated user's customer
        request = self.context.get('request')
        if request and request.user:
            validated_data['customer'] = request.user.customer
        return super().create(validated_data)


class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for Transaction model"""
    account_number = serializers.CharField(source='account.account_number', read_only=True)
    
    class Meta:
        model = Transaction
        fields = ('id', 'account', 'account_number', 'transaction_type', 'amount', 'created_at')
        read_only_fields = ('id', 'created_at')


class DepositSerializer(serializers.Serializer):
    """Serializer for deposit transactions"""
    account_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))

    def validate_account_id(self, value):
        try:
            account = Account.objects.get(id=value)
            self.account = account
            return value
        except Account.DoesNotExist:
            raise serializers.ValidationError("Account does not exist")

    def create(self, validated_data):
        account = self.account
        amount = validated_data['amount']
        
        with transaction.atomic():
            # Update account balance
            account.balance += amount
            account.save()
            
            # Create transaction record
            transaction_obj = Transaction.objects.create(
                account=account,
                transaction_type='deposit',
                amount=amount
            )
        
        return transaction_obj


class WithdrawalSerializer(serializers.Serializer):
    """Serializer for withdrawal transactions"""
    account_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))

    def validate_account_id(self, value):
        try:
            account = Account.objects.get(id=value)
            self.account = account
            return value
        except Account.DoesNotExist:
            raise serializers.ValidationError("Account does not exist")

    def validate(self, attrs):
        amount = attrs['amount']
        if hasattr(self, 'account') and self.account.balance < amount:
            raise serializers.ValidationError("Insufficient balance")
        return attrs

    def create(self, validated_data):
        account = self.account
        amount = validated_data['amount']
        
        with transaction.atomic():
            # Update account balance
            account.balance -= amount
            account.save()
            
            # Create transaction record
            transaction_obj = Transaction.objects.create(
                account=account,
                transaction_type='withdrawal',
                amount=amount
            )
        
        return transaction_obj


class TransferSerializer(serializers.Serializer):
    """Serializer for transfer transactions"""
    from_account_id = serializers.IntegerField()
    to_account_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))

    def validate_from_account_id(self, value):
        try:
            account = Account.objects.get(id=value)
            self.from_account = account
            return value
        except Account.DoesNotExist:
            raise serializers.ValidationError("Source account does not exist")

    def validate_to_account_id(self, value):
        try:
            account = Account.objects.get(id=value)
            self.to_account = account
            return value
        except Account.DoesNotExist:
            raise serializers.ValidationError("Destination account does not exist")

    def validate(self, attrs):
        amount = attrs['amount']
        
        if attrs['from_account_id'] == attrs['to_account_id']:
            raise serializers.ValidationError("Cannot transfer to the same account")
        
        if hasattr(self, 'from_account') and self.from_account.balance < amount:
            raise serializers.ValidationError("Insufficient balance in source account")
        
        return attrs

    def create(self, validated_data):
        from_account = self.from_account
        to_account = self.to_account
        amount = validated_data['amount']
        
        with transaction.atomic():
            # Update balances
            from_account.balance -= amount
            to_account.balance += amount
            from_account.save()
            to_account.save()
            
            # Create transaction records
            withdrawal_transaction = Transaction.objects.create(
                account=from_account,
                transaction_type='transfer',
                amount=amount
            )
            
            Transaction.objects.create(
                account=to_account,
                transaction_type='transfer',
                amount=amount
            )
        
        return withdrawal_transaction
