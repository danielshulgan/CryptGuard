from django.urls import path
from .views import  SignupView, CombinedLoginView, logout_view, dashboard_view, ChangeNameView, PasswordResetView, ChangeEmailView, VerifyEmailView, EmailVerificationSentView

app_name = 'accounts'

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', CombinedLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('change-name/', ChangeNameView.as_view(), name='change_name'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('change-email/', ChangeEmailView.as_view(), name='change_email'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('email-verification-sent/', EmailVerificationSentView.as_view(), name='email_verification_sent'),

]