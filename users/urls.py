# Radhe Radhe

from users.views import UserProfileViewset
from rest_framework.routers import DefaultRouter

routers = DefaultRouter()

routers.register(r'users', UserProfileViewset, basename='user')

urlpatterns = routers.urls
