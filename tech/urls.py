from django.contrib import admin
from django.urls import path, include, re_path
from api.views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf.urls.static import static
from django.conf import settings
from rest_framework.routers import DefaultRouter
from django.conf.urls.static import static
from django.views.static import serve 
from api.views import PasswordResetRequestView, PasswordResetConfirmView
from  api.views import UserListView, UserCreateView, UserRetrieveUpdateDestroyView
from api.views import (
    ServiceListCreateAPIView, ServiceDetailAPIView,
    EquipmentListCreateAPIView, EquipmentDetailAPIView,
    DeaconSupportDetailAPIView, DeaconSupportListCreateAPIView
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/user/register/', UserCreate.as_view(), name='user_create'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api-auth/', include('rest_framework.urls')),
    path('accounts/', include('allauth.urls')),
    path('callback/', google_login_callback, name='callback'),
    path('api/auth/user/', UserDetailView.as_view(), name='user_detail'),
    path('api/google/validate_token/', validate_google_token, name='validate_token'),
    path('api/password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('api/password_reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/create/', UserCreateView.as_view(), name='user-create'),
    path('users/<int:id>/', UserRetrieveUpdateDestroyView.as_view(), name='user-detail'),


    path('api/services/', ServiceListCreateAPIView.as_view(), name='service-list-create'),
    path('api/services/<int:pk>/', ServiceDetailAPIView.as_view(), name='service-detail'),

    path('api/equipment/', EquipmentListCreateAPIView.as_view(), name='equipment-list-create'),
    path('api/equipment/<int:pk>/', EquipmentDetailAPIView.as_view(), name='equipment-detail'),
    path("api/csrf/", csrf_token_view),
    path('deacon-support/', DeaconSupportListCreateAPIView.as_view(), name='deacon-support-list-create'),
    path('deacon-support/<int:pk>/', DeaconSupportDetailAPIView.as_view(), name='deacon-support-detail'),

]
