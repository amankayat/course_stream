from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('username', csrf_exempt(views.Usernamevalidation), name='Usernamevalidation'),
    path('email', csrf_exempt(views.Emailvalidation), name='Emailvalidation'),
    path('login-username', csrf_exempt(views.LoginUsernamevalidation), name='LoginUsernamevalidation'),
    path('password', csrf_exempt(views.currentPassvalidation), name='currentPassvalidation'),
    path('user/login', views.handlelogin, name='handlelogin'),
    path('user/logout', views.handlelogout, name='handlelogout'),
    path('user/signup', views.handleSignup, name='handleSignup'),
    path('course/check-payment/payment-ckecking', csrf_exempt(views.checkpayment), name='checkpayment'),
    path('Courses/check-payment/free/<str:slug>', views.FreeCheckout, name='FreeCheckout'),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',  
        views.activate, name='activate'),  
    path('error/',views.error,name = "error"),
]