from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer, LoginSerializer
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token


class UserCreateView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)

        token, _ = Token.objects.get_or_create(user=user)

        return Response(
            {"token": token.key, **serializer.data}, status=status.HTTP_201_CREATED
        )

    def perform_create(self, serializer):
        return serializer.save()


class LoginView(CreateAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []  # No authentication required for login
    permission_classes = [AllowAny]  # Allow any user to access the login endpoint

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]
            role = serializer.validated_data["role"]
            user = User.objects.get(email=email)
            if user is not None and user.check_password(password) and user.role == role:
                token, _ = Token.objects.get_or_create(user_id=user.id)
                return Response(
                    {"token": str(token.key), "id": user.id}, status=status.HTTP_200_OK
                )
            return Response(
                {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class HelloWorldView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"message": "Hello, World!"}, status=status.HTTP_200_OK)
