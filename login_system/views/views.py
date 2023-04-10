from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as lo
from ..forms.SignupForm import SignupForm
from django.contrib.auth.decorators import login_required


def logout(request):
    lo(request)
    return redirect('login')


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
