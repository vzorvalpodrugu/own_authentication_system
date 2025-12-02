from rest_framework.permissions import BasePermission
from django.http import JsonResponse
from .models import BusinessElement, AccessRule

class CustomPermission(BasePermission):
    """Custom permission class"""

    def has_permission(self, request, view):
        """Check if user has permission"""
        user = getattr(request, 'user', None)

        if not user or not user.is_authenticated():
            return False

        element_name = self._get_element_name(view)
        if not element_name:
            return True

        try:
            element = BusinessElement.objects.get(name=element_name)
        except BusinessElement.DoesNotExist:
            return False

        try:
            access_rule = AccessRule.objects.get(role=user.role, element=element)
        except AccessRule.DoesNotExist:
            return False

        return self._check_method_permission(request.method, access_rule, user, view)

    def has_object_permission(self, request, view, obj):
        """Check permission at the object level"""
        user = getattr(request, 'user', None)

        if not user or not user.is_authenticated():
            return False

        element_name = self._get_element_name(view)
        if not element_name:
            return True

        try:
            element = BusinessElement.objects.get(name=element_name)
            access_rule = AccessRule.objects.get(role=user.role, element=element)
        except (BusinessElement.DoesNotExist ,AccessRule.DoesNotExist):
            return False

        is_owner = self._check_ownership(obj, user)

        return self._check_object_permission(request.method, access_rule, user, is_owner)

    def _get_element_name(self, view):
        """Get business element name from view"""
        element_mapping = {
            'UserViewSet': 'users',
            'ProductViewSet': 'products',
            'OrderViewSet': 'orders',
            'StoreViewSet': 'stores',
            'AccessRuleViewSet': 'access_rules',
        }

        view_name = view.__class__.__name__
        return element_mapping.get(view_name)

    def _check_method_permission(self, method, access_rule, user, view):
        """Checking permission for HTTP method"""
        method_permissions = {
            'GET': access_rule.can_read,
            'POST': access_rule.can_create,
            'PUT': access_rule.can_update,
            'PATCH': access_rule.can_update,
            'DELETE': access_rule.can_delete,
        }

        return method_permissions.get(method, False)

    def _check_ownership(self, obj, user):
        """Проверка, является ли пользователь владельцем объекта"""
        if hasattr(obj, 'owner'):
            return obj.owner == user
        elif hasattr(obj, 'user'):
            return obj.user == user
        elif hasattr(obj, 'created_by'):
            return obj.created_by == user
        return False

    def _check_object_permission(self, method, access_rule, is_owner):
        """Проверка разрешения на уровне объекта"""
        if is_owner:
            # Для владельца проверяем базовые разрешения
            method_permissions = {
                'GET': access_rule.can_read,
                'PUT': access_rule.can_update,
                'PATCH': access_rule.can_update,
                'DELETE': access_rule.can_delete,
            }
        else:
            # Для не-владельца проверяем расширенные разрешения
            method_permissions = {
                'GET': access_rule.can_read_all,
                'PUT': access_rule.can_update_all,
                'PATCH': access_rule.can_update_all,
                'DELETE': access_rule.can_delete_all,
            }

        return method_permissions.get(method, False)

    class IsAdminUser(BasePermission):
        """Разрешение только для администраторов"""

        def has_permission(self, request, view):
            user = getattr(request, 'user', None)
            return user and user.is_authenticated and user.role and user.role.name == 'admin'

    class IsOwnerOrAdmin(BasePermission):
        """Разрешение для владельца или администратора"""

        def has_object_permission(self, request, view, obj):
            user = getattr(request, 'user', None)

            if not user or not user.is_authenticated:
                return False

            # Администратор имеет доступ ко всему
            if user.role and user.role.name == 'admin':
                return True

            # Проверяем владение
            if hasattr(obj, 'owner'):
                return obj.owner == user
            elif hasattr(obj, 'user'):
                return obj.user == user

            return False