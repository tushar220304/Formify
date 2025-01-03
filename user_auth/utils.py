# Radhe Radhe

import jwt
import random
import secrets
from django.conf import settings
from django.utils import timezone
from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError
from rest_framework.exceptions import ValidationError
from datetime import datetime, timedelta


def generate_six_digit_code():
    return random.randint(100000, 999999)


def generate_refresh_key():
    return secrets.token_hex(64) 


def generate_access_key(user):
    payload = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'permissions': user.permissions,
        'active': user.active, 
        'iat': timezone.now(),
        'exp': timezone.now() + timedelta(hours=24)
    }

    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return access_token
    

def is_jwt_expired(exp_date_timestamp):
    '''
    if this function return True it means token is expired
    '''
    if timezone.now() > timezone.make_aware(datetime.fromtimestamp(exp_date_timestamp)):
        return True
    return False


def decode_jwt(token):
    try:
        secret_key = settings.SECRET_KEY
        decoded_data = jwt.decode(token, secret_key, algorithms=["HS256"], verify=True)
        if is_jwt_expired(decoded_data['exp']):
            raise ValidationError('Access Token is already expired')
        return decoded_data
    except ExpiredSignatureError:
        raise ValueError("The token has expired.")
    except DecodeError:
        raise ValueError("The token is invalid.")
    except InvalidTokenError:
        raise ValueError("Invalid token. Could not decode.")