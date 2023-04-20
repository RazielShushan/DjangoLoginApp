import yaml
from .validators_method import *

# Load the password policy configuration from a YAML file
with open(r'C:\Users\almog\DjangoLoginApp\login_system\password_policy.yml', 'r') as f:
    config = yaml.safe_load(f)

min_length = config.get('min_length', 8)
require_uppercase = config.get('require_uppercase', True)
require_lowercase = config.get('require_lowercase', True)
require_numeric = config.get('require_numeric', True)
require_special = config.get('require_special', True)
common_password = config.get('common_password', True)
numeric_password = config.get('numeric_password', True)


def validate_password(password, user=None):
    password_validators = [
        MinimumLengthValidator(min_length),
        CommonPasswordValidator() if common_password else None,
        NumericPasswordValidator() if numeric_password else None,
        HasUpperCaseValidator() if require_uppercase else None,
        HasLowerCaseValidator() if require_lowercase else None,
        HasSymbolValidator() if require_special else None,
        NumericPasswordValidator() if require_numeric else None,
    ]
    custom_validate(password, user, password_validators)
