from django.db import models

class User(models.Model):
    username = models.CharField(max_length=100,null=True,blank=True)
    firstName = models.CharField(max_length=100,null=True,blank=True)
    middleName = models.CharField(max_length=100,null=True,blank=True)
    lastName = models.CharField(max_length=100,null=True,blank=True)
    password = models.CharField(max_length=100,null=True,blank=True)
    token=models.CharField(max_length=100,null=True,blank=True)

    def __str__(self):
        return self.username