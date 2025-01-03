#  Radhe Radhe

from datetime import timedelta
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from user_auth.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from django.contrib.auth import authenticate
from django.utils import timezone

from user_auth.models import RefreshToken
from users.models import UserProfile
from users.serializers import UserProfileSerializer
from user_auth.utils import generate_six_digit_code, generate_access_key, generate_refresh_key, decode_jwt, is_jwt_expired


def get_user(email):
    if email:
        try:
            user = UserProfile.objects.get(email__iexact=email)
            return user
        except UserProfile.DoesNotExist:
            raise ValidationError({'error': True, 'message': 'User Does not exists'})
        except Exception as e:
            raise ValidationError({'error': True, 'message': e.args[0]})
    else:
        raise ValidationError({'error': True, 'message': 'Email is missing'})


class UserRegister(APIView):
    permission_classes = []

    def post(self, request):
        try:
            serializer = UserProfileSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            # add a logic for the sending activation code
            return Response({'error': False, 'message': 'User Registered successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)
        

class ActivateUser(APIView):
    permission_classes = []
    
    def post(self, request):
        try:
            code = request.data.get('code')
            user = get_user(request.data.get('email'))
            if code == user.code and not user.active:
                user.active = True
                user.code = None
                user.save()
                return Response({'error': False, 'message': 'User Activated successfully'}, status=status.HTTP_200_OK)
            else: 
                return Response({'error': True, 'message': 'Wrong code entered'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)


class ResendCode(APIView):
    permission_classes = []
    
    def post(self, request):
        try:
            code = generate_six_digit_code()
            user = get_user(request.data.get('email'))
            user.code = code
            # add a function to send the resend code email
            user.save()
            return Response({'error': False, 'message': 'Verification code resent successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class LoginUser(APIView):

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            
            if not email or not password:
                raise AuthenticationFailed({'error': True, 'message': 'Email or password is missing.'})
            
            user = authenticate(email=email, password=password)

            if not user:
                raise AuthenticationFailed({'error': True, 'message': 'Authentication Failed'})
            
            token, created = RefreshToken.objects.get_or_create(user=user)
            access_key = generate_access_key(user)
            if created or not token.is_valid() or token.force_expire:
                print('its here')
                token.refresh_key = generate_refresh_key()
                token.expire_at = timezone.now() + timedelta(days=7)
            token.force_expire = False
            token.save()
            user.last_login = timezone.now()
            user.save()

            return Response(
                {
                    'error': False,
                    'message': {
                        'keys': {
                            'access_key': access_key,
                            'refresh_key': token.refresh_key
                        }
                    }
                }
            )

        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)
        
    
class LogOutUser(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token is not None:
                try:
                    rt = RefreshToken.objects.get(refresh_key=refresh_token)
                    if not rt.is_valid():
                        raise ValidationError('Access token is already expired')
                    rt.refresh_key = None
                    rt.force_expire = True
                    rt.save()
                except RefreshToken.DoesNotExist:
                    raise ValidationError('Invalid refresh token')
                return Response({'error': False, 'message': 'User Logged out successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)
        

class GetNewAccessToken(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token is not None:
                try:
                    rt = RefreshToken.objects.get(refresh_key=refresh_token)
                    if not rt.is_valid():
                        raise ValidationError({'error': True, 'message': 'Access token is already expired'})
                    access_token = generate_access_key(request.user)
                    return Response({'error': False, 'access_token': access_token}, status=status.HTTP_200_OK)
                except RefreshToken.DoesNotExist:
                    raise ValidationError('Invalid refresh token')
        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            user = request.user
            old_password = request.data.get('old_password')
            new_password = request.data.get('new_password')
            if not user.check_password(old_password):
                return Response({'error': True, 'message': 'Wrong password'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({'error': False, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)



class ForgotPassword(APIView):

    def post(self, request):
        try:
            if request.query_params.get('send_mail', False):
                # send the email to the user 
                # forgot_password_mail(request.data.get('email'))
                # ...
                return Response({'error': False, 'message': 'working fine'}, status=status.HTTP_200_OK)
            user = request.user
            payload = request.query_params.get('i')
            user_detail = decode_jwt(payload)  # update this code
            if is_jwt_expired(user_detail('exp')):
                return Response({'error': True, 'message': 'Forgot Password mail expired please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)
            user = get_user(user_detail.get('email'))
            # decode this jwt payload it will contain the 
            # it will contain the email, expiry, password, cnf_password
            if user_detail['password'] != user_detail['cnf_password']:
                return Response({'error': True, 'message': 'Password and Confirm password did not match'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(user_detail['password'])
            user.save()
            return Response({'error': False, 'message': 'New password created successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': True, 'message': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)
        

