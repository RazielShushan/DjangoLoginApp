from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm


def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return render(request, 'success.html')
        else:
            return render(request, 'login.html', {'error_message': 'Invalid login credentials'})

    return render(request, 'login.html')


def reset_password(request):
    return render(request, 'reset_password.html')


def forgot_password(request):
    return render(request, 'forgot_password.html')


def home(request):
    return render(request, 'home.html')


def signup(request):
    if request.user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('/')
        else:
            return render(request, 'signup.html', {'form': form})
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})
