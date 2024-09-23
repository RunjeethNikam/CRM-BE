from rest_framework import serializers
from .models import Ticket

from django.contrib.auth import get_user_model
from comments.models import Comment

User = get_user_model()


class CommentSerializer(serializers.ModelSerializer):
    posted_by = serializers.CharField(source="posted_by.username", read_only=True)

    class Meta:
        model = Comment
        fields = ["id", "text", "created_at", "posted_by"]
        read_only_fields = ["created_at", "posted_by"]


class TicketListSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.username", read_only=True)
    comments = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = [
            "id",
            "subject",
            "description",
            "assigned",
            "created_by",
            "comments",
            "status",
            "created_at",
        ]

    def get_comments(self, obj):
        sorted_comments = obj.comments.order_by('-created_at')
        return CommentSerializer(sorted_comments, many=True).data


class TicketSerializer(serializers.ModelSerializer):
    assigned = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = Ticket
        fields = [
            "subject",
            "description",
            "assigned",
            "created_by",
            "status",
            "created_at",
            "archive",
        ]
        extra_kwargs = {"archive": {"default": False}}
