# Radhe Radhe

from django.db import models
from django.utils.timezone import now
from users.models import UserProfile


# Temporary model for the storing Refresh token bcoz w'll store it in redis

class RefreshToken(models.Model):
    user = models.OneToOneField(UserProfile, related_name='refresh_token', on_delete=models.CASCADE)
    refresh_key = models.TextField(unique=True, null=True)
    created_at = models.DateTimeField(auto_now=True)
    expire_at = models.DateTimeField(blank=True, null=True)
    force_expire = models.BooleanField(default=False) # True when user log out
 
    def __str__(self):
        return f'Token for {self.user.email}'
    
    def is_valid(self):
        return self.expire_at > now()