from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from user_auth.utils import decode_jwt, is_jwt_expired
from user_auth.models import UserProfile

class JWTAuthentication(BaseAuthentication):
    
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthenticationFailed("Authentication Failed No JWT Token provied. Expected: jwt <token>")  # No authentication attempted

        # The expected header format is: "jwt <token>"
        try:
            token_type, token = auth_header.split()
        except ValueError:
            raise AuthenticationFailed("Invalid Authorization header format. Expected: jwt <token>")

        if token_type.lower() != "jwt":
            raise AuthenticationFailed("Invalid token type. Expected: jwt")

        # Decode and validate the token
        decoded_data = decode_jwt(token)
        if is_jwt_expired(decoded_data['exp']):
            raise AuthenticationFailed('Access token is already expired')

        # Fetch the user based on the token payload
        user_email = decoded_data.get("email")
        if not user_email:
            raise AuthenticationFailed("Token payload is missing user_id")
        
        try:
            user = UserProfile.objects.get(email__iexact=user_email)
        except UserProfile.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, decoded_data)
