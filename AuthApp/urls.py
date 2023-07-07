from django.urls import path
from .views import LoginView,LogoutView,ForgotPasswordAPIView,ResetPasswordAPIView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot/',ForgotPasswordAPIView.as_view()),
    path('reset-password/<str:token>/', ResetPasswordAPIView.as_view(), name='reset_password'),
]