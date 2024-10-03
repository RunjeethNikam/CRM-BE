from django.urls import path
from .views import TicketListView, TicketCreateView, TicketArchiveUpdateView

urlpatterns = [
    path("", TicketListView.as_view(), name="tickets"),
    path("create/", TicketCreateView.as_view(), name="create_tickets"),
    # path("update-status/<str:pk>", UpdateTicketStatusView.as_view(), name="create_tickets"),
    path('update-status/<str:pk>/', TicketArchiveUpdateView.as_view(), name='create_tickets'),
]
