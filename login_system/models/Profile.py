import hmac
import hashlib
from django.db import models
from communication_system.settings import AUTH_USER_MODEL


""" class CustomUser(User):
    def save(self, *args, **kwargs):
        # Generate a custom salt and HMAC value
        salt = "12"
        secret_key = "123"
        message = self.username.encode('utf-8')
        hmac_value = hmac.new(salt.encode('utf-8'),
                              message, hashlib.sha256).hexdigest()

        # Set the custom salt and HMAC value in the user's attributes
        self.salt = salt
        self.hmac_value = hmac_value

        # Call the superclass's save() method to save the user in the database
        super(CustomUser, self).save(*args, **kwargs)
"""


class Profile(models.Model):
    user = models.OneToOneField(
        AUTH_USER_MODEL, on_delete=models.CASCADE)
    email = models.EmailField()
    forget_password_token = models.CharField(max_length=100)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)


"""" class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, parent_link=True)
    email = models.EmailField()
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    """
