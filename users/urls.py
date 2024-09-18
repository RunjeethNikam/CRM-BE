from django.urls import path
from .views import UserCreateView, LoginView, HelloWorldView

urlpatterns = [
    path("signin/", UserCreateView.as_view(), name="user-create"),
    path("login/", LoginView.as_view(), name="login"),
    path("hello-world/", HelloWorldView.as_view(), name="helloworld")
]
