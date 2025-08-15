from django.urls import path
from .views import RegisterAPI, LoginAPI, DashboardAPI, LogoutAPI


urlpatterns = [
    # path('register/',views.register, name='register'),
    # path('login/',views.login_view, name='login'),
    # path('dashboard/',views.dashboard, name='dashboard'),
    # path('meeting/',views.videocall, name='meeting'),
    # path('logout/',views.logout_view, name='logout'),
    # path('join/',views.join_room, name='join_room'),
    # path('',views.index, name='index'),
    path('api/register/', RegisterAPI.as_view(), name='api_register'),
    path('api/login/', LoginAPI.as_view(), name='api_login'),
    path('api/dashboard/', DashboardAPI.as_view(), name='api_dashboard'),
    path('api/logout/', LogoutAPI.as_view(), name='api_logout'),

]