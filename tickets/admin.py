from django.contrib import admin
from .models import Ticket

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('subject', 'created_by', 'assigned', 'id')
    search_fields = ('subject', 'description')
    list_filter = ('assigned', 'created_by')
