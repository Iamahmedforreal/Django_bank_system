from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .models import Customer, Account, Transaction
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, CustomerSerializer,
    AccountSerializer, TransactionSerializer, DepositSerializer,
    WithdrawalSerializer, TransferSerializer, SecureIBANTransferSerializer
)
from .logging_utils import bank_logger, get_client_ip, log_api_request


class IsOwnerOrStaff(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or staff to access it.
    """
    def has_object_permission(self, request, view, obj):
        # Staff can access everything
        if request.user.is_staff:
            return True
        
        # Check if the object belongs to the user
        if hasattr(obj, 'customer'):
            return obj.customer.user == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'account'):
            return obj.account.customer.user == request.user
        
        return False


class IsStaffOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow staff to create/edit.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return request.user.is_staff


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_view(request):
    """
    Register a new user and create associated customer.
    """
    log_api_request(request, '/api/auth/register/')
    
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = serializer.save()
            
            # Log successful registration
            bank_logger.log_security_event(
                'USER_REGISTRATION',
                user,
                {
                    'ip_address': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'email': user.email
                }
            )
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'message': 'User created successfully',
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.customer.first_name,
                    'last_name': user.customer.last_name,
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            # Log registration failure
            bank_logger.log_security_event(
                'REGISTRATION_FAILURE',
                None,
                {
                    'ip_address': get_client_ip(request),
                    'error': str(e),
                    'attempted_username': request.data.get('username', 'unknown')
                },
                severity='ERROR'
            )
            return Response({
                'error': 'Registration failed',
                'detail': 'An error occurred during registration'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Log validation errors
    bank_logger.log_security_event(
        'REGISTRATION_VALIDATION_ERROR',
        None,
        {
            'ip_address': get_client_ip(request),
            'errors': serializer.errors,
            'attempted_username': request.data.get('username', 'unknown')
        },
        severity='WARNING'
    )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login_view(request):
    """
    Login user and return JWT tokens.
    """
    log_api_request(request, '/api/auth/login/')
    
    username = request.data.get('username', 'unknown')
    ip_address = get_client_ip(request)
    
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Log successful login
        bank_logger.log_authentication_attempt(
            username, 
            success=True, 
            ip_address=ip_address,
            details={'user_id': user.id}
        )
        
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Login successful',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.customer.first_name,
                'last_name': user.customer.last_name,
            }
        }, status=status.HTTP_200_OK)
    
    # Log failed login attempt
    bank_logger.log_authentication_attempt(
        username,
        success=False,
        ip_address=ip_address,
        details={'errors': serializer.errors}
    )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerViewSet(ModelViewSet):
    """
    ViewSet for Customer model.
    Only staff can access all customers.
    Regular users can only see their own customer profile.
    """
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [permissions.IsAuthenticated, IsStaffOrReadOnly]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Customer.objects.all()
        else:
            return Customer.objects.filter(user=self.request.user)


class AccountViewSet(ModelViewSet):
    """
    ViewSet for Account model.
    Users can only access their own accounts.
    Staff can access all accounts.
    """
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrStaff]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Account.objects.all()
        else:
            return Account.objects.filter(customer__user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user.customer)


class TransactionViewSet(ModelViewSet):
    """
    ViewSet for Transaction model.
    Users can only see transactions for their own accounts.
    Staff can see all transactions.
    """
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrStaff]
    http_method_names = ['get', 'head', 'options']  # Read-only

    def get_queryset(self):
        if self.request.user.is_staff:
            return Transaction.objects.all()
        else:
            return Transaction.objects.filter(account__customer__user=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def deposit_view(request):
    """
    Deposit money into an account.
    """
    serializer = DepositSerializer(data=request.data)
    if serializer.is_valid():
        # Check if user owns the account or is staff
        account = serializer.account
        if not request.user.is_staff and account.customer.user != request.user:
            return Response(
                {'error': 'You can only deposit to your own accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        transaction_obj = serializer.save()
        transaction_serializer = TransactionSerializer(transaction_obj)
        return Response(transaction_serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def withdrawal_view(request):
    """
    Withdraw money from an account.
    """
    serializer = WithdrawalSerializer(data=request.data)
    if serializer.is_valid():
        # Check if user owns the account or is staff
        account = serializer.account
        if not request.user.is_staff and account.customer.user != request.user:
            return Response(
                {'error': 'You can only withdraw from your own accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        transaction_obj = serializer.save()
        transaction_serializer = TransactionSerializer(transaction_obj)
        return Response(transaction_serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def transfer_view(request):
    """
    Transfer money between accounts.
    """
    serializer = TransferSerializer(data=request.data)
    if serializer.is_valid():
        # Check if user owns the source account or is staff
        from_account = serializer.from_account
        if not request.user.is_staff and from_account.customer.user != request.user:
            return Response(
                {'error': 'You can only transfer from your own accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        transaction_obj = serializer.save()
        transaction_serializer = TransactionSerializer(transaction_obj)
        return Response(transaction_serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def secure_iban_transfer_view(request):
    """
    Secure IBAN-based money transfer with enhanced authentication.
    Only authenticated users can send money from their own accounts.
    
    Required fields:
    - recipient_iban: Target account IBAN
    - amount: Transfer amount
    - source_account_id: Source account ID (must belong to authenticated user)
    - description: Optional transfer description
    """
    serializer = SecureIBANTransferSerializer(data=request.data)
    
    if serializer.is_valid():
        # Additional security check: Ensure user owns the source account
        source_account = serializer.source_account
        
        # Check if user owns the source account or is staff
        if not request.user.is_staff and source_account.customer.user != request.user:
            return Response(
                {
                    'error': 'Access denied',
                    'detail': 'You can only transfer from your own accounts'
                },
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Log the transfer attempt for security monitoring
        log_api_request(request, '/api/banking/secure-transfer/', request.user)
        
        bank_logger.log_transfer_attempt(
            request.user,
            source_account.id,
            serializer.validated_data['recipient_iban'],
            str(serializer.validated_data['amount']),
            success=True  # Will be updated if it fails
        )
        
        try:
            # Execute the transfer
            transaction_obj = serializer.save()
            
            # Return success response with transaction details
            return Response({
                'success': True,
                'message': 'Transfer completed successfully',
                'transaction': {
                    'id': transaction_obj.id,
                    'amount': str(transaction_obj.amount),
                    'source_account': source_account.account_number,
                    'source_iban': source_account.iban,
                    'recipient_iban': serializer.validated_data['recipient_iban'],
                    'description': transaction_obj.description,
                    'created_at': transaction_obj.created_at,
                    'status': 'completed'
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            # Log the error for security monitoring
            bank_logger.log_transfer_attempt(
                request.user,
                source_account.id,
                serializer.validated_data['recipient_iban'],
                str(serializer.validated_data['amount']),
                success=False,
                error_message=str(e)
            )
            
            return Response(
                {
                    'error': 'Transfer failed',
                    'detail': 'An error occurred while processing the transfer'
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response({
        'error': 'Validation failed',
        'details': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)
