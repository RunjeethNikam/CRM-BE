from django.urls import path
from .views import TicketListView, TicketCreateView, TicketArchiveUpdateView

urlpatterns = [
    path("", TicketListView.as_view(), name="tickets"),
    path("create/", TicketCreateView.as_view(), name="create_tickets"),
    path('tickets/<int:pk>/archive/', TicketArchiveUpdateView.as_view(), name='ticket-archive-update'),
]
