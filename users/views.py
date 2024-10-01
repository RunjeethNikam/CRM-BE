import random
import string

from .models import User
from users import serializers as user_serializers
from .permissions import IsAdminUser

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import update_session_auth_hash
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404

from django.utils.http import urlsafe_base64_decode

from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from rest_framework import generics, response, status, views


class UserCreateView(generics.CreateAPIView):
    queryset = User.objects.filter(deleted=False)
    serializer_class = user_serializers.UserCreateSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)

        token, _ = Token.objects.get_or_create(user=user)

        return response.Response(
            {"token": token.key, **serializer.data}, status=status.HTTP_201_CREATED
        )

    def perform_create(self, serializer):
        return serializer.save()


class LoginView(generics.CreateAPIView):
    serializer_class = user_serializers.LoginSerializer
    authentication_classes = []  # No authentication required for login
    permission_classes = [AllowAny]  # Allow any user to access the login endpoint

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]
            role = serializer.validated_data["role"]
            user = get_object_or_404(User, email=email)
            if user is not None and user.check_password(password) and user.role == role:
                token, _ = Token.objects.get_or_create(user_id=user.id)
                return response.Response(
                    {"token": str(token.key), "id": user.id, "username": user.username},
                    status=status.HTTP_200_OK,
                )
            return response.Response(
                {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AddUserView(views.APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = user_serializers.AddUserSerializer(data=request.data)
        if serializer.is_valid():
            random_password = "".join(
                random.choices(string.ascii_letters + string.digits, k=8)
            )
            hashed_password = make_password(random_password)
            serializer.save(password=hashed_password)

            return response.Response(
                {"password": random_password},
                status=status.HTTP_201_CREATED,
            )
        else:
            return response.Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = user_serializers.PasswordResetRequestSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.get(email=email)

        # Generate password reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Create password reset URL
        password_reset_url = (
            f"{request.scheme}://{request.get_host()}/reset-password/{uid}/{token}/"
        )

        # Send email to the user
        subject = "Password Reset Requested"
        message = f"""
        Hi {user.username},

        You requested a password reset. Click the link below to reset your password:

        {password_reset_url}

        If you did not request this, please ignore this email.

        Best regards,
        Your Application Team
        """
        send_mail(subject, message, from_email=None, recipient_list=[user.email])

        return response.Response(
            {"message": "Password reset email sent."}, status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = user_serializers.PasswordResetSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return response.Response(
                {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not default_token_generator.check_token(user, token):
            return response.Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Set new password
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return response.Response(
            {"message": "Password reset successful."}, status=status.HTTP_200_OK
        )


class HelloWorldView(views.APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return response.Response(
            {"message": "Hello, World!"}, status=status.HTTP_200_OK
        )


class UserTicketView(views.APIView):
    def get(self, request):
        user_type = request.query_params.get("type", None)
        user_type = user_type.upper()

        if user_type not in [User.ROLE_CUSTOMER, User.ROLE_EMPLOYEE]:
            return response.Response(
                {"error": 'Invalid type parameter. Use "employee" or "customer".'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Filter users based on role
        users = User.objects.filter(role=user_type.upper())

        if not users.exists():
            return response.Response(
                {"message": "No users found for the given type."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Serialize the data
        serializer = user_serializers.UserSerializer(users, many=True)

        return response.Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetView(views.APIView):

    def post(self, request):
        serializer = user_serializers.PasswordResetSerializer(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data["new_password"])
            user.save()

            # Keep the user logged in after password reset
            update_session_auth_hash(request, user)

            return response.Response(
                {"message": "Password updated successfully."}, status=status.HTTP_200_OK
            )

        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SoftDeleteUserView(generics.GenericAPIView):
    permission_classes = [IsAdminUser]  # Only allow admins to delete users

    def post(self, request, *args, **kwargs):
        # Get the user by ID (this assumes the user ID is passed in the URL)
        user_id = kwargs.get("user_id")
        user = get_object_or_404(User, id=user_id)

        # If the user is already marked as deleted
        if user.deleted:
            return response.Response(
                {"message": "User is already deleted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Mark the user as deleted
        user.deleted = True
        user.save()

        # Reassign the user's tickets
        self.reassign_tickets(user)
        self.delete_tokens(user)

        return response.Response(
            {"message": "User deleted successfully."}, status=status.HTTP_200_OK
        )

    def reassign_tickets(self, user):
        # Find all tickets assigned to this user
        from tickets.models import Ticket

        tickets = Ticket.objects.filter(assigned=user)

        # Reassign the tickets to the new employee
        for ticket in tickets:
            new_assignee = (
                User.objects.filter(role="EMPLOYEE", deleted=False)
                .order_by("?")
                .first()
            )
            ticket.assigned = new_assignee
            ticket.save()

    def delete_tokens(self, user):
        Token.objects.filter(user=user).delete()
