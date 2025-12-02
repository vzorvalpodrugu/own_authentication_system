from django.contrib.auth.models import BaseUserManager
from .models import Role

class UserManager(BaseUserManager):
    """Custom user model manager"""

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('The email must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        """Creates and saves a new superuser"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')

        admin_role, _ = Role.objects.get_or_create(name='admin')
        extra_fields['role'] = admin_role

        return self.create_user(email, password, **extra_fields)


