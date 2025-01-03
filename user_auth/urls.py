# Radhe Radhe


from django.urls import path
from user_auth.views import UserRegister, ActivateUser, ResendCode, LoginUser, \
            LogOutUser, GetNewAccessToken, ResetPassword, ForgotPassword

urlpatterns = [
    path('register/', UserRegister.as_view(), name='user_registeration'),
    path('activate-user/', ActivateUser.as_view(), name='activate-user'),
    path('resend-code/', ResendCode.as_view(), name='resend-code'),
    path('login/', LoginUser.as_view(), name='login-user'),
    path('logout/', LogOutUser.as_view(), name='logout-user'),
    path('get-new-access-token/', GetNewAccessToken.as_view(), name='get-new-access-token'),
    path('reset-password/', ResetPassword.as_view(), name='reset-password'),
    path('forgot-password/', ForgotPassword.as_view(), name='forgot-password')
]