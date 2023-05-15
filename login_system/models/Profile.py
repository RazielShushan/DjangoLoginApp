from django.db import models
from communication_system.settings import AUTH_USER_MODEL


class Profile(models.Model):
    user = models.OneToOneField(
        AUTH_USER_MODEL, on_delete=models.CASCADE)
    email = models.EmailField()
    forget_password_token = models.CharField(
        max_length=100, null=True, default=None)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
