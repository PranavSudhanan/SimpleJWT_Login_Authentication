from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.response import Response
from .models import UserModel
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import check_password,make_password
from .models import PasswordResetToken
from django.core.mail import send_mail
from django.urls import reverse
import secrets
from TokenAuth.settings import EMAIL_HOST_USER

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = UserModel.objects.filter(username=username).first()

        if user and check_password(password, user.password):
            access_token = AccessToken.for_user(user)

            # Update the user's access token
            user.token = str(access_token)
            user.is_active = True
            user.save()

            return JsonResponse({
                'token': str(access_token)
            })
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)
        

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        authorization_header = request.headers.get('Authorization')

        if authorization_header and authorization_header.startswith('Bearer '):
            access_token = authorization_header.split(' ')[1]
        else:
            return Response({'error': 'Invalid authorization header'}, status=400)

        try:
            user_model = UserModel.objects.get(token=access_token)
        except UserModel.DoesNotExist:
            return Response({'error': 'User not found'}, status=400)

        if user_model.token == access_token:
            # Clear the access token
            user_model.token = None
            user_model.save()
            return Response({'message': 'Logout successful'})
        else:
            return Response({'error': 'Invalid access token'}, status=400)


class ForgotPasswordAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            UserModel.objects.get(email=email)  # Assuming UserModel is the model representing user login information
        except UserModel.DoesNotExist:
            return Response({'error': 'No user found with the provided email.'}, status=400)

        token = secrets.token_urlsafe(32)

        # Save the token in the PasswordResetToken model
        password_reset_token = PasswordResetToken.objects.create(token=token, email=email)
        password_reset_token.save()

        reset_url = request.build_absolute_uri(
            reverse('reset_password', kwargs={'token': token})
        )

        # Send an email to the user with the reset password link
        send_mail(
            'Reset Your Password',
            f'Please click the following link to reset your password: {reset_url}',
            EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return Response({'message': 'An email has been sent to your email address with instructions to reset your password.'})

class ResetPasswordAPIView(APIView):
    def post(self, request, token):
        try:
            password_reset_token = PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return Response({'error': 'Invalid token.'}, status=400)

        email = password_reset_token.email
        new_password = request.data.get('new_password')

        # Update the user's password
        user = UserModel.objects.get(email=email)
        user.password = make_password(new_password)
        user.save()

        # Delete the password reset token
        password_reset_token.delete()

        return Response({'message': 'Your password has been reset successfully.'})