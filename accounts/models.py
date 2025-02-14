import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(
        self, 
        email, 
        first_name, 
        last_name, 
        date_of_birth, 
        contact, 
        is_signed_agreement, 
        password=None
        ):
        """
        Creates and saves a regular user with the given email, first name, last name, date of birth, contact, and password.
        """
        if not email:
            raise ValueError("The Email field must be set")
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            contact=contact,
            is_signed_agreement=is_signed_agreement,
        )
        
        user.set_password(password)  
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, date_of_birth, contact, password=None):
        """
        Creates and saves a superuser with the given email, first name, last name, date of birth, and password.
        """
        user = self.create_user(
            email,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            contact=contact,
            is_signed_agreement=timezone.now(),  
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True 
        user.is_superuser = True

        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    date_of_birth = models.DateField()
    contact = models.CharField(max_length=255)
    is_signed_agreement = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)  
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "first_name", 
        "last_name", 
        "date_of_birth", 
        "contact",
    ]  

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
