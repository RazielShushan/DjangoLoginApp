from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from ..models import Account as User
import pytz
from datetime import datetime, timedelta
from ..models.LoginAttempt import LoginAttempt
import yaml
from communication_system.settings import PASSWORD_POLICY_FILE_PATH

# Load the password policy configuration from a YAML file
with open(PASSWORD_POLICY_FILE_PATH, 'r') as f:
    config = yaml.safe_load(f)

MAX_LOGIN_ATTEMPTS = config.get('max_login_attempts', 3)
BLOCK_DURATION = config.get('block_duration', 5)  # in minutes


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Check if user with given username exists
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'login.html', {'error_message': 'Invalid login credentials'})
        # Check the user's password and count login attempts
        if not user.is_active:
            return render(request, 'login.html', {'error_message': 'Your account has been blocked due to too many unsuccessful login attempts. Pleasecontact support for assistance.'})
        if user is not None:
            userauth = authenticate(
                request, username=username, password=password)
            if not userauth:
                gmt = pytz.timezone('GMT')
                timestamp = datetime.now(
                    gmt)-timedelta(minutes=BLOCK_DURATION)
                login_attempts = LoginAttempt.objects.filter(
                    user=user, timestamp__gte=timestamp).count() + 1
                if login_attempts >= MAX_LOGIN_ATTEMPTS:
                    # Block the user
                    user.is_active = False
                    user.save()
                    return render(request, 'login.html', {'error_message': "Your account has been blocked due to too many unsuccessful login attempts. Please try again later."})

                else:
                    # Increment the number of login attempts
                    LoginAttempt.objects.create(user=user)
                    return render(request, 'login.html', {'error_message': "Please enter a correct username and password. Note that your account will be blocked after {} unsuccessful login attempts.".format(MAX_LOGIN_ATTEMPTS)})

            else:
                login(request, user)
                return redirect('home')
        else:
            return render(request, 'login.html', {'error_message': 'Invalid login credentials'})

    return render(request, 'login.html')
