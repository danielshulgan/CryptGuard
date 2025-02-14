from django.db import models
from django.conf import settings  

class OTP(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  
    otp_secret = models.CharField(max_length=16)
    email = models.EmailField(unique=False)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.email