# models.py
import uuid
import random
import string
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class Ticket(models.Model):

    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('CLOSED', 'Closed'),
    ]

    id = models.CharField(primary_key=True, max_length=20, editable=False, unique=True)
    subject = models.CharField(max_length=255)
    description = models.TextField()
    assigned = models.ForeignKey(
        User,
        related_name="assigned_tickets",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        User,
        related_name="created_tickets",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')
    created_at = models.DateTimeField(default=timezone.now)
    archive = models.BooleanField(default=False)

    def __str__(self):
        return self.subject
    
    def save(self, *args, **kwargs):
        if not self.id:
            last_ticket = Ticket.objects.all().order_by('created_at').last()

            if last_ticket:
                last_id = int(last_ticket.id.split('-')[-1])
                new_id = last_id + 1
            else:
                new_id = 1

            # Generate the new ticket ID with the format 'CRM-TID-0000001'
            self.id = f"CRM-TID-{new_id:07d}"  # Ensures the number is padded to 7 digits

        super(Ticket, self).save(*args, **kwargs)

