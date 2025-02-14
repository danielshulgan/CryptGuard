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

class PasswordResetForm(forms.Form):
    new_password = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput
    )
    confirm_password = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        max_length=254, 
        widget=forms.EmailInput(
            attrs={'placeholder': 'Email'}
        )
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={'placeholder': 'Password'}
        )
    )

class EmailResetForm(forms.Form):
    current_email = forms.EmailField(
        label="Current Email Address",
        required=True
    )
    new_email = forms.EmailField(
        label="New Email Address",
        required=True
    )
    confirm_new_email = forms.EmailField(
        label="Confirm New Email Address",
        required=True
    )

    def clean(self):
        cleaned_data = super().clean()
        new_email = cleaned_data.get("new_email")
        confirm_new_email = cleaned_data.get("confirm_new_email")

        if new_email and confirm_new_email and new_email != confirm_new_email:
            self.add_error(
                'confirm_new_email', 
                "New email addresses do not match."
        )

        return cleaned_data

class UpdateNameForm(forms.Form):
    first_name = forms.CharField(
        label="First Name",
        max_length=255, 
        required=True)
    last_name = forms.CharField(
        label="Last Name",
        max_length=255, 
        required=True)

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data