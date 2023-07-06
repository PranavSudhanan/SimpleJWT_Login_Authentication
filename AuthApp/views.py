from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.response import Response
from .models import User
from rest_framework.permissions import IsAuthenticated


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()

        if user and user.password == password:
            access_token = AccessToken.for_user(user)

            # Update the user's access token
            user.token = str(access_token)
            user.save()

            return JsonResponse(
                {
                    'access': str(access_token)
                }
            )
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)
        

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        authorization_header = request.headers.get('Authorization')
        access_token = None

        if authorization_header:
            # Extract the token from the Authorization header
            try:
                access_token = authorization_header.split(' ')[1]
            except IndexError:
                pass

        if access_token:
            try:
                # Delete the access token from the database
                user = User.objects.filter(token=access_token).first()
                if user:
                    user.token = None
                    user.save()
                    return Response({'message': 'Logout successful'})

                return Response({'error': 'Already Logged Out'}, status=400)
            except:
                return Response({'error': 'Invalid access token'}, status=400)
        else:
            return Response({'error': 'Access token not provided'}, status=400)


