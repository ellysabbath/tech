from django.contrib import admin
from django.urls import path, include, re_path
from api.views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from django.views.static import serve

# DRF router for viewsets
router = DefaultRouter()
router.register(r'departments', DepartmentsViewSet, basename='departments')
router.register(r'department-contents', DepartmentContentsViewSet, basename='department-contents')
router.register(r'department-members', DepartmentMembersViewSet, basename='department-members')
router.register(r'department-reports', DepartmentReportsViewSet, basename='department-reports')

urlpatterns = [
    path('admin/', admin.site.urls),

    # User & auth endpoints
    path('api/user/register/', UserCreateView.as_view(), name='user_create'),
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
    path('users/<int:pk>/', UserRetrieveUpdateDestroyAPIView.as_view(), name='user-detail'),

    # Service & equipment
    path('api/services/', ServiceListCreateAPIView.as_view(), name='service-list-create'),
    path('api/services/<int:pk>/', ServiceDetailAPIView.as_view(), name='service-detail'),
    path('api/equipment/', EquipmentListCreateAPIView.as_view(), name='equipment-list-create'),
    path('api/equipment/<int:pk>/', EquipmentDetailAPIView.as_view(), name='equipment-detail'),

    # CSRF & deacon support
    path("api/csrf/", csrf_token_view),
    path('deacon-support/', DeaconSupportListCreateAPIView.as_view(), name='deacon-support-list-create'),
    path('deacon-support/<int:pk>/', DeaconSupportDetailAPIView.as_view(), name='deacon-support-detail'),

    # Contacts & messages
    path('contacts/', ContactListCreateAPIView.as_view(), name='contact-list-create'),
    path('contacts/<int:pk>/', ContactRetrieveUpdateDestroyAPIView.as_view(), name='contact-detail'),
    path('messages/', MessageListCreateAPIView.as_view(), name='message-list-create'),
    path('messages/<int:pk>/', MessageRetrieveUpdateDestroyAPIView.as_view(), name='message-detail'),
    path('sms/callback/', AfricasTalkingSMSCallbackAPIView.as_view(), name='sms-callback'),

    # Announcements
    path('announcements/', AnnouncementsListCreateAPIView.as_view(), name='announcements-list-create'),
    path('announcements/<int:pk>/', AnnouncementsDetailAPIView.as_view(), name='announcements-detail'),

    # Timetables
    path('timetables/', TimetableListCreateAPIView.as_view(), name='timetable-list-create'),
    path('timetables/<int:pk>/', TimetableDetailAPIView.as_view(), name='timetable-detail'),
    path('timetables/<int:pk>/download/', TimetableDownloadAPIView.as_view(), name='timetable-download'),

    # User profile
    path('users/me/', UserProfileView.as_view(), name='user_profile'),

    # Department-specific endpoints
    path('api/departments/<int:department_id>/contents/', DepartmentContentsByDepartment.as_view(), 
         name='department-contents-list'),
    path('api/departments/by-name/<str:department_name>/contents/', DepartmentContentsByName.as_view(),
         name='department-contents-by-name'),

    # Include video conference app URLs
    path('', include('videoconference_app.urls')),


       # Existing department content endpoints
    path('api/departments/<int:department_id>/contents/', 
         DepartmentContentsByDepartment.as_view(), 
         name='department-contents-list'),
    path('api/departments/by-name/<str:department_name>/contents/', 
         DepartmentContentsByName.as_view(),
         name='department-contents-by-name'),
    
    # New department member endpoints
    path('api/departments/<int:department_id>/members/', 
         DepartmentMembersByDepartment.as_view(), 
         name='department-members-list'),
    path('api/members/by-number/<str:membership_number>/', 
         DepartmentMembersByMembershipNumber.as_view(),
         name='department-members-by-number'),
        path('api/departments/<int:department_id>/reports/', 
         DepartmentReportsByDepartment.as_view(), 
         name='department-reports-list'),
    path('api/reports/by-type/<str:report_type>/', 
         DepartmentReportsByType.as_view(),
         name='department-reports-by-type'),

    # Include router URLs (maintains existing /api/departments/ and /api/department-contents/ endpoints)
    path('api/', include(router.urls)),
]

# Serve media files in development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)