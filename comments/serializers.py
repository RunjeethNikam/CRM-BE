from rest_framework import serializers
from .models import Comment, Ticket
from django.contrib.auth import get_user_model


class CommentCreateSerializer(serializers.ModelSerializer):
    ticket_id = serializers.CharField(write_only=True)
    text = serializers.CharField()

    class Meta:
        model = Comment
        fields = ["ticket_id", "text"]

    def create(self, validated_data):
        # Fetch the ticket object using the provided ticket_id
        ticket = Ticket.objects.get(id=validated_data["ticket_id"])

        # Create the comment
        comment = Comment.objects.create(
            text=validated_data["text"],
            ticket=ticket,
            posted_by=self.context["request"].user,
        )
        return comment
