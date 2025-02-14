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




    