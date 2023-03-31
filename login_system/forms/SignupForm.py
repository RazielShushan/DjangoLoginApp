from django import forms
from django.contrib.auth.forms import UserCreationForm
# from django.contrib.auth.models import User
from ..models import Account as User
from ..validators.password_policy import validate_password
from django.core.exceptions import (
    ValidationError,
)


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True, label='Email', max_length=255,
                             help_text='Required. Enter a valid email address.')

    class Meta:
        model = User
        fields = ('email', 'username', 'password1', 'password2', )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                self.error_messages["password_mismatch"],
                code="password_mismatch",
            )
        validate_password(password2, self.instance)
        return password2
