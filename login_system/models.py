import hmac
import hashlib
from django.db import models
from django.contrib.auth.models import User


class CustomUser(User):
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


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField()
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
