from django.urls import path
from .import views

urlpatterns = [
    path('login/', views.login_view),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('signup/', views.signup, name='signup'),
    path('', views.home, name='home')
]
