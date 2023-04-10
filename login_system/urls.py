from django.urls import path
from .views import views, login_view

urlpatterns = [
    path('login/', login_view.login_view, name='login'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('signup/', views.signup, name='signup'),
    path('profile/', views.profile, name='profile'),
    path('', views.home, name='home'),
    path('logout/', views.logout, name='logout'),
]
