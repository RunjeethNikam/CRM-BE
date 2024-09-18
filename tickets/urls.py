from django.urls import path
from .views import TicketListView, TicketCreateView

urlpatterns = [
    path("", TicketListView.as_view(), name="tickets"),
    path("create/", TicketCreateView.as_view(), name="create_tickets"),
]
