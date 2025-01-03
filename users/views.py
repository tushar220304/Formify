# Radhe Radhe

from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework import status
from users.models import UserProfile
from users.serializers import UserProfileSerializer


class UserProfileViewset(ModelViewSet):
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.get_active()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()  # this will return the user instance
        return Response({'error': False, **serializer.data}, status=status.HTTP_201_CREATED)

