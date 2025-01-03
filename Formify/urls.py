# Radhe Radhe

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('user_auth.urls')),
    path('api/', include('users.urls')),
    path('api/', include('forms_app.urls')),
]
