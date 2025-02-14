from django.urls import path
from . import views
from .views import ResetPasswordView, DashboardView, LoginView, SignupView, ChangeEmailView, ChangeNameView


app_name = 'accounts'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),  
    path('logout/', views.logout_view, name='logout'),  
    path('signup/', SignupView.as_view(), name='signup'), 
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('change-email/', ChangeEmailView.as_view(), name='change_email'),  
    path('change-name/', ChangeNameView.as_view(), name='change_name'),
]