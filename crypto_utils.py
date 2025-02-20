import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def get_derived_key():
    # Retrieve the master key and salt from environment variables
    master_key = os.getenv('VAULT_MASTER_KEY')
    salt = os.getenv('VAULT_SALT', 'default_salt').encode('utf-8')
    
    if not master_key:
        raise ValueError("VAULT_MASTER_KEY is not set in the environment.")
    
    master_key = master_key.encode('utf-8')
    
    # Use PBKDF2HMAC to derive a 32-byte key (for AES-256)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(master_key)
    # Fernet requires a URL-safe base64-encoded 32-byte key.
    return base64.urlsafe_b64encode(derived_key)