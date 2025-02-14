# otp/urls.py
from django.urls import path
from .views import SendOTPView, VerifyOTPView, LoginOTPView
from accounts.views import LoginView

app_name = 'otp_auth'

urlpatterns = [
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-login-otp/', LoginOTPView.as_view(), name='verify_login_otp'),
]