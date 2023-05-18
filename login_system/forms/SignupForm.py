from django import forms
from django.contrib.auth.forms import UserCreationForm
from ..models import Account as User
from ..validators.password_policy import validate_password
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import (
    ValidationError,
)


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True, label='Email', max_length=255,
                             help_text='Required. Enter a valid email address.')
    username = forms.CharField(
        max_length=200,  # Set the desired maximum length for the username field
        help_text=_(
            'Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )

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
