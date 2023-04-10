from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as lo
from .forms.SignupForm import SignupForm
from django.contrib.auth.decorators import login_required
from .models import Account as User

import pytz
from datetime import datetime, timedelta
from .models.LoginAttempt import LoginAttempt
from django.core.exceptions import ValidationError


MAX_LOGIN_ATTEMPTS = 3
BLOCK_DURATION = 5  # in minutes


def logout(request):
    lo(request)
    return redirect('login')


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


def reset_password(request):
    return render(request, 'reset_password.html')


def forgot_password(request):
    return render(request, 'forgot_password.html')


@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')


@login_required
def profile(request):
    user = request.user
    context = {
        'user': user,
    }
    return render(request, 'profile.html', context)


def signup(request):
    if request.user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            user.save()
            login(request, user)
            return redirect('home')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})
