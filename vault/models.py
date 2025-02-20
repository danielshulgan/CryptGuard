from django.db import models

import os
from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from cryptography.fernet import Fernet, InvalidToken
from crypto_utils import get_derived_key  # Adjust the import path based on your project structure

User = get_user_model()

class VaultItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="vault_items")
    service = models.CharField(max_length=255)
    login_email = models.EmailField()
    # We store the encrypted password as a text field (base64 encoded)
    encrypted_password = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, raw_password):
        """
        Encrypts and sets the password using Fernet (which uses AES under the hood).
        """
        key = get_derived_key()
        f = Fernet(key)
        encrypted = f.encrypt(raw_password.encode('utf-8'))
        self.encrypted_password = encrypted.decode('utf-8')

    def get_password(self):
        """
        Decrypts and returns the password.
        """
        key = get_derived_key()
        f = Fernet(key)
        try:
            decrypted = f.decrypt(self.encrypted_password.encode('utf-8'))
            return decrypted.decode('utf-8')
        except InvalidToken:
            return None

    def __str__(self):
        return f"{self.service} ({self.login_email})"
