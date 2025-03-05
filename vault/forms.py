from django import forms
from .models import VaultItem

class VaultItemForm(forms.ModelForm):
    # We'll use a custom field for the raw password input.
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput,
        required=True
    )
    
    class Meta:
        model = VaultItem
        fields = ['service', 'login_email', 'password']
        
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_password(self.cleaned_data["password"])
        if commit:
            instance.save()
        return instance