from django.urls import path
from .views import login_view
from .views import views
from django.views.generic.base import RedirectView
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('login/', login_view.login_view, name='login'),
    path('change_password/', views.change_password, name='change_password'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('signup/', views.signup, name='signup'),
    path('profile/', views.profile, name='profile'),
    path('', views.home, name='home'),
    path('logout/', views.logout, name='logout'),
    path('forgot/<token>/', views.password_reset_confim,
         name='password_reset_confirm'),
    path('forgot_password_complete/', views.forgot_password_complete,
         name='password_reset_complete'),


]
