import yaml
from .validators_method import *
from communication_system.settings import PASSWORD_POLICY_FILE_PATH


# Load the password policy configuration from a YAML file
with open(PASSWORD_POLICY_FILE_PATH, 'r') as f:
    config = yaml.safe_load(f)

min_length = config.get('min_length', 8)
require_uppercase = config.get('require_uppercase', False)
require_lowercase = config.get('require_lowercase', False)
require_numeric = config.get('require_numeric', False)
require_special = config.get('require_special', False)
common_password = config.get('common_password', False)
numeric_password = config.get('numeric_password', False)


def validate_password(password, user=None):
    password_validators = [
        MinimumLengthValidator(min_length),
        CommonPasswordValidator() if common_password else None,
        NumericPasswordValidator() if numeric_password else None,
        HasUpperCaseValidator() if require_uppercase else None,
        HasLowerCaseValidator() if require_lowercase else None,
        HasSymbolValidator() if require_special else None,
        NumericPasswordValidator() if require_numeric else None,
        LastThreePasswordsValidator()
    ]
    custom_validate(password, user, password_validators)


def get_password_policy_config():
    return {
        'min_length': min_length,
        'require_uppercase': require_uppercase,
        'require_lowercase': require_lowercase,
        'require_numeric': require_numeric,
        'require_special': require_special,
        'common_password': common_password,
        'numeric_password': numeric_password,
    }
