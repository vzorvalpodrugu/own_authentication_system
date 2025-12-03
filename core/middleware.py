from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
import jwt
from django.conf import settings
from .models import User, UserSession

class TokenAuthMiddleware(MiddlewareMixin):
    """Middleware for authenticating requests with JWT tokens"""

    def process_request(self, request):
        # Pass public endpoint
        public_paths = ['/api/auth/login/', '/api/auth/register/', '/admin/']
        if any(request.path.startswith(path) for path in public_paths):
            return None

        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer'):
            request.user = None
            return None

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=settings.JWT_ALGORITHM,
            )

            if payload['token_type'] != 'access':
                request.user = None
                return None

            user_id = payload['user_id']

            try:
                user = User.objects.get(id=user_id, is_active=True)

                session_exists = UserSession.objects.filter(
                    user=user,
                    token=token,
                    is_active=True
                ).exists()

                if session_exists:
                    request.user = user
                else :
                    request.user = None

            except User.DoesNotExist:
                request.user = None

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'token has expired'}, status=401)
        except jwt.InvalidTokenError:
            request.user = None

        return None

class PermissionMiddleware(MiddlewareMixin):
    """Middleware for checking permissions"""

    def process_view(self, request, view_func, view_args, view_kwargs):
        """if view required auth, but user not found"""
        if hasattr(view_func, 'permission_classes'):
            user = getattr(view_func, 'user', None)

            if not user or not user.is_authenticated:
                for permission_class in view_func.permission_classes:
                    permission = permission_class()
                    if hasattr(permission, 'requires_authentication') and permission.requires_authentication:
                        return JsonResponse({'error': 'Authentication required'}, status=401)
        return None