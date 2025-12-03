from rest_framework import serializers
from core.models import (
    User,
    Role,
    BusinessElement,
    AccessRule,
    Product,
    Order,
    Store
)

class UserRegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'middle_name', 'password', 'password_confirm']

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError('Passwords do not match')
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'middle_name', 'role_name', 'created_at']
        read_only_fields =['id', 'email', 'role_name', 'created_at']

class BusinessElementSerializer(serializers.ModelSerializer):
    """Serializer for business element"""
    class Meta:
        model = BusinessElement
        fields = ['id', 'name', 'description', 'table_name', 'created_at']


class AccessRuleSerializer(serializers.ModelSerializer):
    """Serializer for access rule"""
    role_name = serializers.CharField(source='role.name', read_only=True)
    element_name = serializers.CharField(source='element.name', read_only=True)

    class Meta:
        model = AccessRule
        fields = '__all__'

