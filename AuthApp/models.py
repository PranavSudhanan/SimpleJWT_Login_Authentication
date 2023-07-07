from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.utils import timezone


class UserModel(models.Model):
    username=models.CharField(max_length=100,null=True,blank=True)
    firstName=models.CharField(max_length=100,null=True,blank=True)
    middleName=models.CharField(max_length=100,null=True,blank=True)
    lastName=models.CharField(max_length=100,null=True,blank=True)
    email=models.EmailField(null=True,blank=True)
    companyId=models.CharField(max_length=20,null=True,blank=True)
    location=models.CharField(max_length=200,null=True,blank=True)
    contact=models.CharField(max_length=15,null=True,blank=True)
    password=models.CharField(max_length=100,null=True,blank=True)
    token=models.CharField(max_length=100,null=True,blank=True)
    last_login=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_active=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.pk:  # New object being created
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

class PasswordResetToken(models.Model):
    token = models.CharField(max_length=255, unique=True)
    email = models.EmailField()
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.email