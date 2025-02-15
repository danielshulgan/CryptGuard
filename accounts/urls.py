from django.urls import path
from .views import  SignupView, CombinedLoginView, logout_view, dashboard_view, ChangeNameView, PasswordResetView

app_name = 'accounts'

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', CombinedLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('change-name/', ChangeNameView.as_view(), name='change_name'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),


]