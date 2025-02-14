from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from otp_auth.models import OTP

User = get_user_model()

@receiver(pre_delete, sender=User)
def delete_related_otp(sender, instance, **kwargs):
    try:
        otp = OTP.objects.get(user=instance)
        otp.delete()
    except OTP.DoesNotExist:
        pass
