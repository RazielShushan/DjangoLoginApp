from django import forms
from django.contrib.auth.forms import UserCreationForm
from ..models import User


class SignupForm(UserCreationForm):
    email = forms.EmailField(
        max_length=255, help_text='Required. Enter a valid email address.')

    class Meta:
        model = User
        fields = ('email', 'password1', 'password2')
