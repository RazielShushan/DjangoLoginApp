from django.shortcuts import render, redirect
from django.db import connection
from .models import Account
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as lo
from .forms.SignupForm import SignupForm
from django.contrib.auth.decorators import login_required
from datetime import datetime


def logout(request):
    lo(request)
    return redirect('login')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
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
            now = datetime.now()
            email = request.POST.get('email')
            username = request.POST.get('username')
            password = request.POST.get('password1')
            firstname = ''
            last_name = ''
            date_joined = now.strftime("%Y-%m-%d %H:%M:%S")
            last_login = now.strftime("%Y-%m-%d %H:%M:%S")
            is_admin = '0'
            is_active = '1'
            is_staff = '0'
            is_superuser = '0'
            query = "INSERT INTO login_system_account (first_name,last_name,date_joined,last_login,is_admin,is_active,is_staff,is_superuser, username, email, password) VALUES ('" + \
                firstname + "','" + last_name + "','" + date_joined + "','" + last_login + "','" + is_admin + "','" + is_active + "','" + is_staff + "','" + is_superuser + "','" + username + "','" + email + \
                    "','" + password + "');"
            cursor = connection.cursor()

            try:
                cursor.execute(query)
                connection.commit()
                user = Account.objects.get(email=email)

                login(request, user)
                return redirect('home')
            except Exception as e:
                form.errors['__all__'] = form.error_class(
                    [str(e) + '\n' + query])
                return render(request, 'signup.html', {'form': form})
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})
