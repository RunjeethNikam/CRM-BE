from django.urls import path
from users import views as user_views

urlpatterns = [
    path("signin/", user_views.UserCreateView.as_view(), name="user-create"),
    path("login/", user_views.LoginView.as_view(), name="login"),
    path("hello-world/", user_views.HelloWorldView.as_view(), name="helloworld"),
    path("add-employee/", user_views.AddUserView.as_view(), name="create-user"),
    path("", user_views.UserTicketView.as_view(), name="get-users"),
    path("change-password/", user_views.PasswordResetView.as_view(), name="change-password"),
    path("delete-user/<int:user_id>", user_views.SoftDeleteUserView.as_view(), name="change-password"),
    # path('request-password-reset/', user_views.PasswordResetRequestView.as_view(), name='request-password-reset'),
    # path('reset-password/<uidb64>/<token>/', user_views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
]
