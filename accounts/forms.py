from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        label="Email",
        required=True
    )
    first_name = forms.CharField(
        label="First Name",
        max_length=255, 
        required=True
    )
    last_name = forms.CharField(
        label="Last Name",
        max_length=255, 
        required=True
    )
    date_of_birth = forms.DateField(
        label="Date of Birth (MM/DD/YYYY)",
        required=True
    )
    contact = forms.CharField(
        label="Phone (###-###-####)",
        max_length=255, 
        required=True
    )

    class Meta:
        model = User 
        fields = [
            'first_name', 
            'last_name', 
            'email', 
            'date_of_birth', 
            'contact', 
            'password1', 
            'password2']  
        
class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={'placeholder': 'Email', 'class': 'form-control'}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Password', 'class': 'form-control'}),
    )

class OTPForm(forms.Form):
    otp = forms.CharField(
        label="One-Time Password",
        max_length=6,
        widget=forms.TextInput(attrs={'placeholder': 'Enter OTP', 'class': 'form-control'}),
    )

class ChangeNameForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name']

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Enter your registered email", widget=forms.EmailInput(attrs={'class': 'form-control'}))

class OTPPasswordResetForm(forms.Form):
    otp = forms.CharField(label="Enter OTP", max_length=6, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'OTP'}))
    new_password1 = forms.CharField(label="New Password", widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'}))
    new_password2 = forms.CharField(label="Confirm New Password", widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm New Password'}))



    