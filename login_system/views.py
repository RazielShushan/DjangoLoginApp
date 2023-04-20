from django.shortcuts import render, redirect
from django.contrib.auth.views import PasswordResetView as BasePasswordResetView
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as lo
from .forms.SignupForm import SignupForm
from django.db.models.query_utils import Q
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from .models import *
import hashlib
from .validators.password_policy import validate_password
from django.contrib import messages
import uuid

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

#####################
def forgot_password(request):
    User = get_user_model()
    if request.method == "POST":
        data = request.POST.get('email')
        user = User.objects.filter(Q(email=data)).first()
        if user is not None:
                subject = "Password Reset Requested"
                email_template_name = "password_reset_email.html"
                val = str(uuid.uuid4())
                token =  hashlib.sha1(val.encode())
                c = {
					"email":user.email,
					'domain':'127.0.0.1:8000',
					'site_name': 'Website',
					"uid": urlsafe_base64_encode(force_bytes(user.pk)),
					"user": user,
					'token':token.hexdigest(),
					'protocol': 'http',
					}
                try:
                    user.set_token(token)
                    user.save()
                except Exception as e:
                    print(e)
                email = render_to_string(email_template_name, c)
                try:
                    send_mail(subject, email, 'communicationssysteminc@gmail.com' , [user.email], fail_silently=False)
                except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                return render(request,"password_reset_done.html")
    return render(request=request, template_name="password_reset_form.html")

def password_reset_confim(request,token):
    try:
        User = get_user_model()
        user_obj = User.objects.filter(forget_password_token = token).first()
        context = {'user_id':user_obj.id}
        if request.method == "POST":
            new_password = request.POST.get('new_password')
            password_confirm = request.POST.get('new_password_confirm')
            user_id = request.POST.get('user_id')

            if user_id is None:
                messages.error(request, 'No user id was found')
                return render(request, 'password_reset_confirm.html', context)
            
            if new_password != password_confirm:
                messages.error(request, 'Password confirmation does not match the password entered')
                return render(request, 'password_reset_confirm.html', context)
            try:
                validate_password(new_password)
            except Exception as e:
                print(e)
                messages.error(request, 'Password does not match policy')
                return render(request, 'password_reset_confirm.html', context) 
            user_obj = User.objects.get(id = user_id)
            user_obj.set_password(new_password)
            user_obj.check_password
            user_obj.save()
            return render(request,'password_reset_complete.html')

        return render(request,'password_reset_confirm.html',context)
    except Exception as ex:
        return render(request, 'login.html', {'error_message': 'Invalid reset password link'})


def forgot_password_complete(request):
    return render(request,'password_reset_complete.html')
#################
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
            # raw_password = form.cleaned_data.get('password1')
            # user = authenticate(username=user.username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})
