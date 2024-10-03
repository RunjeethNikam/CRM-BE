from rest_framework import permissions
from users import models as user_models

class IsEmployee(permissions.BasePermission):
    """
    Custom permission to only allow users with the 'ADMIN' role to access certain views.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == user_models.User.ROLE_EMPLOYEE
