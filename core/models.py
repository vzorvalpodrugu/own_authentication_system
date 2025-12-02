from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, \
    UserManager
from django.utils import timezone
import bcrypt
import jwt
from datetime import datetime, timedelta
from django.conf import settings

# from .managers import UserManager

class Role(models.Model):
    """Users Role Model"""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'roles'

    def __str__(self):
        return self.name

class BusinessElement(models.Model):
    """Business Element Model"""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    table_name = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'business_elements'

    def __str__(self):
        return self.name

class AccessRule(models.Model):
    """Model of access rule for roles to business elements"""
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='access_rules')
    element = models.ForeignKey(BusinessElement, on_delete=models.CASCADE, related_name='access_rules')

    # based rules
    can_create = models.BooleanField(default=False)
    can_read = models.BooleanField(default=False)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)

    # advanced rules
    can_read_all = models.BooleanField(default=False)
    can_update_all = models.BooleanField(default=False)
    can_delete_all = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'access_rules'
        unique_together = ['role', 'element']

    def __str__(self):
        return f'{self.role.name} -> {self.element.name}'

class User(AbstractUser, PermissionsMixin):
    """Custom User Model"""
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    middle_name = models.CharField(max_length=50, blank=True)

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='users')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    class Meta:
        db_table = 'users'

    def __str__(self):
        return self.email

    def set_password(self, raw_password):
        """Password hashing using bcrypt"""
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(raw_password.encode('utf-8'), salt).decode('utf-8')

    def generate_token(self, token_type='access'):
        """Generate JWT token"""
        if token_type == 'access':
            expires_at = datetime.now() + settings.JWT_ACCESS_TOKEN_LIFETIME
        else:
            expires_at = datetime.now() + settings.JWT_REFRESH_TOKEN_LIFETIME

        payload = {
            'user_id': self.id,
            'email': self.email,
            'role': self.role,
            'token_type': token_type,
            'exp': expires_at,
            'iat': datetime.now(),
        }

        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    def soft_delete(self):
        """Soft delete user"""
        self.is_active = False
        self.deleted_at = datetime.now()
        self.save()

class UserSession(models.Model):
    """User Session Model"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    token = models.TextField()
    refresh_token = models.TextField()
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'user_sessions'

    def is_expired(self):
        return timezone.now() > self.expires_at

class AuditLog(models.Model):
    """Audit Log Model"""
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    element = models.ForeignKey(BusinessElement, on_delete=models.CASCADE, null=True, blank=True)
    record_id = models.IntegerField(null=True, blank=True)
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_log'
        ordering = ['-created_at']


class Product(models.Model):
    """Model of product(mock object)"""
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.IntegerField(default=0)
    owner = models.ForeignKey(User, on_delete=models.CASCADE,
                              related_name='products')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'products'

    def __str__(self):
        return self.name


class Order(models.Model):
    """Model of order(mock object)"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name='orders')
    product = models.ForeignKey(Product, on_delete=models.CASCADE,
                                related_name='orders')
    quantity = models.IntegerField(default=1)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES,
                              default='PENDING')
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'orders'

    def __str__(self):
        return f"Order #{self.id} by {self.user.email}"


class Store(models.Model):
    """Model of store(mock object)"""
    name = models.CharField(max_length=200)
    address = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE,
                              related_name='stores')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'stores'

    def __str__(self):
        return self.name