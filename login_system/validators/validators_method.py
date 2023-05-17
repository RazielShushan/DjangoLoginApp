from django.core.exceptions import ValidationError
import re
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import *
from ..models.PreviousPassword import PreviousPassword


def custom_validate(password, user=None, password_validators=None):
    errors = []
    if password_validators is None:
        password_validators = get_default_password_validators()
    for validator in password_validators:
        if validator is not None:
            try:
                validator.validate(password, user)
            except ValidationError as error:
                errors.append(error)
    if errors:
        raise ValidationError(errors)


class _ValidatorBase():
    __slots__ = ('message',)
    DEFAULT_MSG = ''

    def __init__(self, message=None):
        self.message = message if message else self.DEFAULT_MSG

    def get_help_text(self):
        return self.message

    def validate(self, *args, **kwargs):
        raise NotImplementedError()


class HasLowerCaseValidator(_ValidatorBase):
    __slots__ = ()
    DEFAULT_MSG = "The password must contain at least one lowercase character."

    def validate(self, password, user=None):
        if re.search('[a-z]', password) is None:
            raise ValidationError(self.message, code='missing_lower_case')


class HasUpperCaseValidator(_ValidatorBase):
    __slots__ = ()
    DEFAULT_MSG = "The password must contain at least one uppercase character."

    def validate(self, password, user=None):
        if re.search('[A-Z]', password) is None:
            raise ValidationError(self.message, code='missing_upper_case')


class HasNumberValidator(_ValidatorBase):
    __slots__ = ()
    DEFAULT_MSG = "The password must contain at least one numeric character."

    def validate(self, password, user=None):
        if re.search('[0-9]', password) is None:
            raise ValidationError(self.message, code='missing_numeric')


class HasSymbolValidator(_ValidatorBase):
    __slots__ = ()
    DEFAULT_MSG = "The password must contain at least one non-alphanumeric character (symbol)."

    def validate(self, password, user=None):
        if re.search('[^A-Za-z0-9]', password) is None:
            raise ValidationError(self.message, code='missing_symbol')


class LastThreePasswordsValidator:
    _slots__ = ()
    DEFAULT_MSG = "Your new password cannot be one of the last three passwords you used."

    def validate(self, password, user=None):
        if user is None:
            return

        last_three_passwords = PreviousPassword.objects.filter(
            user=user).order_by('-created_at')[:3]
        for last_password in last_three_passwords:
            if check_password(password, last_password.password):
                raise ValidationError(self.DEFAULT_MSG)

        def get_help_text(self):
            return self.DEFAULT_MSG
