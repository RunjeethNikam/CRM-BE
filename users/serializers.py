# serializers.py
from rest_framework import serializers
from .models import User

from tickets.models import Ticket
from tickets import serializers as tickets_serializers


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "role", "password", "joined_date"]

    def create(self, validated_data):
        validated_data["email"] = validated_data["email"].lower().strip()
        validated_data["username"] = validated_data["username"].lower().strip()
        user = User(
            username=validated_data["username"],
            email=validated_data["email"],
            role=validated_data["role"],
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


class AddUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "username", "role", "joined_date"]
        read_only_fields = ["role"]

    def create(self, validated_data):
        validated_data["role"] = User.ROLE_EMPLOYEE
        validated_data["deleted"] = False

        return super().create(validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    role = serializers.ChoiceField(
        choices=[("ADMIN", "Admin"), ("EMPLOYEE", "Employee"), ("CUSTOMER", "Customer")]
    )


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Ensure that the email exists in the database.
        """
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "No user is associated with this email address."
            )
        return value


class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class UserSerializer(serializers.ModelSerializer):
    assigned_tickets = tickets_serializers.TicketListSerializer(
        many=True, read_only=True
    )
    created_tickets = tickets_serializers.TicketListSerializer(
        many=True, read_only=True
    )

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "role",
            "assigned_tickets",
            "created_tickets",
            "joined_date",
            "deleted"
        ]


class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)

    def validate_old_password(self, value):
        """
        Ensure that the old password is correct.
        """
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
