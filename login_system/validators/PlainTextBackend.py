from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

# Relevant to the non secure version
class PlainTextBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            # Compare the plain text password with the password stored in the database
            if password == user.password:
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
