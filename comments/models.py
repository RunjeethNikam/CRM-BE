from django.db import models
from django.contrib.auth import get_user_model
from uuid import uuid4
from tickets.models import Ticket

class Comment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    posted_by = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='comments')
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='comments')

    def __str__(self):
        return f'Comment by {self.posted_by} on {self.ticket}'
