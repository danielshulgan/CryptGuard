from django import forms

class EmailForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254)  

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, label="Enter OTP")  