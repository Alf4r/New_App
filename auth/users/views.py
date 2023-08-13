from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer
from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import User
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import generics, permissions
import jwt, datetime
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found:')
    
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect Password!')
        
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            'token': access_token,
            'refresh_token': refresh_token
        })
    
class CustomTokenRefreshView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')

            if not refresh_token:
                return Response({'error': 'Refresh token not provided.'})

            refresh = RefreshToken(refresh_token)

            # Mengecek apakah token valid dan masih berlaku
            if not refresh.payload.get('token_type') == 'refresh' or not refresh.is_valid():
                return Response({'error': 'Invalid or expired refresh token.'})

            access_token = str(refresh.access_token)
            return Response({'access_token': access_token})
    
        except Exception as e:
            return Response({'error': 'Failed to refresh token.'})
class VerifyTokenView(APIView):
    def post(self, request):
        token = request.data.get('token')

        if not token:
            return Response({'error': 'Token not provided.'})

        try:
            access_token = AccessToken(token)
            access_token.verify()
            return Response({'message': 'Token is valid.'})
        except TokenError as e:
            return Response({'error': str(e)})
def react(request):
    return render(request, 'app.tsx')

    #  payload = {
    #         'id' : user.id,
    #         'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
    #         'iat' : datetime.datetime.utcnow()
    #     }

    # token = jwt.encode(payload, 'secret', algorithm='HS256')
    

    # response = Response()
    # response.set_cookie(key='jwt', value=token, httponly=True)
    # response.data = {
    # 'token' : token
    #  }
    # return response

        

# fitur token paling sederhana tapi sulit diimplementasikan