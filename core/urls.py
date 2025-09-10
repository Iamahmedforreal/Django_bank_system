from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'customers', views.CustomerViewSet)
router.register(r'accounts', views.AccountViewSet)
router.register(r'transactions', views.TransactionViewSet)

# The API URLs are now determined automatically by the router
urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.register_view, name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # 2FA endpoints
    path('auth/2fa/enable/', views.enable_2fa_view, name='enable_2fa'),
    path('auth/2fa/send-otp/', views.send_otp_view, name='send_otp'),
    path('auth/2fa/verify-otp/', views.verify_otp_view, name='verify_otp'),
    
    # Banking operations
    path('banking/deposit/', views.deposit_view, name='deposit'),
    path('banking/withdraw/', views.withdrawal_view, name='withdraw'),
    path('banking/transfer/', views.transfer_view, name='transfer'),
    path('banking/secure-transfer/', views.secure_iban_transfer_view, name='secure_iban_transfer'),
    
    # Include router URLs
    path('', include(router.urls)),
]
