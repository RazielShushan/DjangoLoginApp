from django.forms import ValidationError
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as lo
from ..forms.SignupForm import SignupForm
from ..forms.CustomerForm import CustomerForm
from ..forms.ChangePasswordForm import ChangePasswordForm
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.views import PasswordResetView as BasePasswordResetView
from django.core.mail import send_mail
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
from ..models import *
from ..models.PreviousPassword import PreviousPassword
from ..models.Customer import Customer
import hashlib
from ..validators.password_policy import validate_password, get_password_policy_config
from django.contrib import messages
import uuid
from django.urls import reverse
from django.utils.html import strip_tags

from django.contrib.auth.hashers import make_password
from django.db import connection
from ..models import Account

from datetime import datetime


def logout(request):
    lo(request)
    return redirect('login')


@login_required(login_url='login')
def change_password(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            try:
                validate_password(
                    request.POST['new_password1'], user=request.user)
            except ValidationError as error:
                form.add_error('new_password1', error)
            else:
                user = form.save()
                PreviousPassword.objects.create(
                    user=user, password=user.password)
                update_session_auth_hash(request, user)  # Important!
                messages.success(
                    request, 'Your password was successfully updated!')
                return redirect('change_password')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = ChangePasswordForm(user=request.user)
    return render(request, 'change_password.html', {'form': form})


@login_required(login_url='login')
def home(request):
    if request.method == 'POST':
        form = CustomerForm(request.POST)
        if form.is_valid():
            name = request.POST.get('name')
            phone = request.POST.get('phone')
            address = request.POST.get('address')

            query = "INSERT INTO login_system_customer (name,phone,address) VALUES ('" + \
                name + "','" + phone + "','" + address + "');" + \
                    "SELECT * FROM login_system_customer WHERE id = LAST_INSERT_ID();"
            try:
                cursor = connection.cursor()
                cursor.execute(query)
                table1 = cursor.fetchall()
                cursor.nextset()
                table2 = cursor.fetchall()
                for item in table2[0]:
                    print(item)
                latest_customer = {
                    'name': table2[0][1],
                    'phone': table2[0][2],
                    'address': table2[0][3],
                }
            except Exception as e:
                form.errors['__all__'] = form.error_class(
                    [str(e) + "query: " + query])
                return render(request, 'home.html', {'form': form, 'error': str(e) + "\n" + query})
    else:
        form = CustomerForm()
        latest_customer = Customer.objects.last()

    context = {'form': form, 'latest_customer': latest_customer}
    return render(request, 'home.html', context)


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

            password = make_password(request.POST.get('password1'))
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
                    "','" + password + "');"\
                    "SELECT * FROM login_system_account WHERE id = LAST_INSERT_ID();"
            cursor = connection.cursor()

            try:
                table1 = ""
                table2 = ""
                cursor.execute(query)
                table1 = cursor.fetchall()
                cursor.nextset()
                table2 = cursor.fetchall()
                user = Account.objects.get(email=email)
                PreviousPassword.objects.create(
                    user=user, password=user.email)
                login(request, user)
                return redirect('home')
            except Exception as e:
                return render(request, 'signup.html', {'form': form, 'error_message': str(e) + " user:" + str(table2)})

    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

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
            token = hashlib.sha1(val.encode())
            c = {
                "email": user.email,
                'domain': request.get_host(),
                'site_name': 'Website',
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "user": user,
                'token': token.hexdigest(),
                'protocol': 'https' if request.is_secure() else 'http',
            }
            try:
                reset_url = reverse('password_reset_confirm', args=[
                                    token.hexdigest()])
                reset_link = '{}://{}{}'.format(c['protocol'],
                                                c['domain'], reset_url)
                c['reset_link'] = reset_link
                email = render_to_string(email_template_name, c)
                plain_message = strip_tags(email)
                user.set_token(token)
                user.save()
            except Exception as e:
                print(e)
            try:
                send_mail(subject, plain_message, 'communicationssysteminc@gmail.com',
                          [user.email], html_message=email, fail_silently=False)
            except BadHeaderError:
                return HttpResponse('Invalid header found.')
            return render(request, "password_reset_done.html")
    return render(request=request, template_name="password_reset_form.html")


def password_reset_confim(request, token):
    try:
        User = get_user_model()
        user_obj = User.objects.filter(forget_password_token=token).first()
        context = {'user_id': user_obj.id,
                   'policy': get_password_policy_config(), }
        if request.method == "POST":
            new_password = request.POST.get('new_password')
            password_confirm = request.POST.get('new_password_confirm')
            user_id = request.POST.get('user_id')

            if user_id is None:
                messages.error(request, 'No user id was found')
                return render(request, 'password_reset_confirm.html', context)

            if new_password != password_confirm:
                messages.error(
                    request, 'Password confirmation does not match the password entered')
                return render(request, 'password_reset_confirm.html', context)
            try:
                validate_password(new_password, user=user_obj)
            except Exception as e:
                print(e)
                messages.error(request, 'Password does not match policy')
                return render(request, 'password_reset_confirm.html', context)
            user_obj = User.objects.get(id=user_id)
            user_obj.set_password(new_password)
            user_obj.check_password
            user_obj.forget_password_token = None
            user_obj.save()
            PreviousPassword.objects.create(
                user=user_obj, password=user_obj.password)
            return render(request, 'password_reset_complete.html')

        return render(request, 'password_reset_confirm.html', context)
    except Exception as ex:
        return render(request, 'login.html', {'error_message': 'Invalid reset password link'})


def forgot_password_complete(request):
    return render(request, 'password_reset_complete.html')
#################
