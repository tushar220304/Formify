# Radhe Radhe

from rest_framework import serializers
from users.models import UserProfile


class UserProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(max_length=255, required=True)
    last_name = serializers.CharField(max_length=255)
    password = serializers.CharField(write_only=True, required=True, min_length=6)
    active = serializers.BooleanField(read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            'email', 'first_name', 'last_name', 'active', 
            'permissions', 'created_at', 'updated_at', 'password'
        ]
    
    def create(self, validated_data):
        return UserProfile.objects.create_user(**validated_data)
