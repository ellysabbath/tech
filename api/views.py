from django.shortcuts import redirect
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from allauth.socialaccount.models import SocialAccount, SocialToken

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

from .models import Message, UserProfile
from .serializers import (
    UserSerializers, 
    MessageSerializer, 
    PasswordResetRequestSerializer, 
    PasswordResetConfirmSerializer
)

from django.shortcuts import redirect
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from allauth.socialaccount.models import SocialAccount, SocialToken

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

from .models import Message, UserProfile
from .serializers import (
    UserSerializers, 
    MessageSerializer, 
    PasswordResetRequestSerializer, 
    PasswordResetConfirmSerializer
)

User = get_user_model()

class UserCreateView(generics.CreateAPIView):
    """
    View for user registration with phoneNumber and role
    """
    queryset = User.objects.all()
    serializer_class = UserSerializers
    permission_classes = [permissions.AllowAny]

class UserLoginView(APIView):
    """
    View for user authentication with JWT token response
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {'detail': 'Please provide username and password'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            
            response_data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'username': user.username,
                'email': user.email,
            }

            try:
                profile = user.userprofile
                response_data.update({
                    'phoneNumber': profile.phoneNumber,
                    'role': profile.role
                })
            except ObjectDoesNotExist:
                pass
                
            return Response(response_data)
        else:
            return Response(
                {'detail': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

class UserDetailView(generics.RetrieveUpdateAPIView):
    """
    View for retrieving and updating user details (no auth required)
    """
    queryset = User.objects.all()
    serializer_class = UserSerializers
    permission_classes = [permissions.AllowAny]  # Changed from IsAuthenticated

    def get_object(self):
        # Allow updating profile without authentication
        if 'id' in self.kwargs:
            return User.objects.get(pk=self.kwargs['id'])
        return self.request.user if self.request.user.is_authenticated else None

    def update(self, request, *args, **kwargs):
        # Don't allow password updates without authentication
        if 'password' in request.data and not request.user.is_authenticated:
            return Response(
                {'detail': 'Authentication required for password changes'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return super().update(request, *args, **kwargs)

class UserListView(generics.ListAPIView):
    """
    View for listing all users
    """
    queryset = User.objects.all()
    serializer_class = UserSerializers
    permission_classes = [permissions.AllowAny]

class UserRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    View for retrieving, updating and deleting users by ID
    """
    queryset = User.objects.all()
    serializer_class = UserSerializers
    permission_classes = [permissions.AllowAny]  # Allow profile updates without auth
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        # Add security checks for sensitive fields
        instance = self.get_object()
        
        # Don't allow role changes without authentication
        if 'role' in request.data and not request.user.is_authenticated:
            return Response(
                {'detail': 'Authentication required for role changes'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Don't allow password updates without authentication
        if 'password' in request.data and not request.user.is_authenticated:
            return Response(
                {'detail': 'Authentication required for password changes'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        # Require authentication for deletion
        if not request.user.is_authenticated:
            return Response(
                {'detail': 'Authentication required for deletion'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return super().destroy(request, *args, **kwargs)

# ... [rest of your views remain unchanged - Google auth, password reset, etc.]

# Your other model views (Service, Equipment, etc.) remain unchanged

@login_required
def google_login_callback(request):
    """
    Callback view for Google OAuth authentication
    """
    user = request.user
    social_account = SocialAccount.objects.filter(
        user=user, 
        provider='google'
    ).first()

    if not social_account:
        return redirect('http://localhost:5173/login/callback/?error=NoSocialAccount')

    token = SocialToken.objects.filter(account=social_account).first()

    if token:
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        try:
            profile = user.userprofile
            return redirect(
                f'http://localhost:5173/login/callback/?access_token={access_token}'
                f'&phoneNumber={profile.phoneNumber}&role={profile.role}'
            )
        except ObjectDoesNotExist:
            return redirect(
                f'http://localhost:5173/login/callback/?access_token={access_token}'
            )
    else:
        return redirect('http://localhost:5173/login/callback/?error=NoGoogleToken')

@csrf_exempt
def validate_google_token(request):
    """
    View for validating Google access tokens
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            google_access_token = data.get('access_token')

            if not google_access_token:
                return JsonResponse(
                    {'detail': 'Access Token is missing.'}, 
                    status=400
                )

            # Add actual validation against Google API here if needed
            return JsonResponse({'valid': True})
            
        except json.JSONDecodeError:
            return JsonResponse(
                {'detail': 'Invalid JSON.'}, 
                status=400
            )
    return JsonResponse(
        {'detail': 'Method not allowed.'}, 
        status=405
    )

class PasswordResetRequestView(APIView):
    """
    View for requesting password reset
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()

            if not user:
                return Response(
                    {'error': 'No such email.'}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = f"http://localhost:5173/reset-password/?uid={uid}&token={token}"

            send_mail(
                subject="Password Reset Request",
                message=f"Click the link to reset your password: {reset_url}",
                from_email="noreply@example.com",
                recipient_list=[email],
            )
            return Response({'detail': 'Password reset link has been sent.'})

        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )

class PasswordResetConfirmView(APIView):
    """
    View for confirming password reset
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uidb64 = serializer.validated_data['uidb64']
                token = serializer.validated_data['token']
                new_password = serializer.validated_data['new_password']

                uid = smart_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)

                if default_token_generator.check_token(user, token):
                    user.set_password(new_password)
                    user.save()
                    return Response(
                        {'detail': 'Password has been reset successfully.'}
                    )
                else:
                    return Response(
                        {'detail': 'Invalid or expired token.'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response(
                    {'detail': 'Invalid user ID.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )

# [Keep all your existing Service, Equipment, DeaconSupportRecord, Contact, and Message views]


# for last models
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404

from .models import Service, Equipment
from .serializers import ServiceSerializer, EquipmentSerializer

# --- SERVICE VIEWS ---

class ServiceListCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        services = Service.objects.all()
        serializer = ServiceSerializer(services, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ServiceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ServiceDetailAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, pk):
        return get_object_or_404(Service, pk=pk)

    def get(self, request, pk):
        service = self.get_object(pk)
        serializer = ServiceSerializer(service)
        return Response(serializer.data)

    def put(self, request, pk):
        service = self.get_object(pk)
        serializer = ServiceSerializer(service, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        service = self.get_object(pk)
        service.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# --- EQUIPMENT VIEWS ---

from rest_framework.permissions import AllowAny

class EquipmentListCreateAPIView(APIView):
    permission_classes = [AllowAny]  # ← Allow public access

    def get(self, request):
        equipment = Equipment.objects.all()
        serializer = EquipmentSerializer(equipment, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = EquipmentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EquipmentDetailAPIView(APIView):
    permission_classes = [AllowAny]  # ← Allow public access

    def get_object(self, pk):
        return get_object_or_404(Equipment, pk=pk)

    def get(self, request, pk):
        equipment = self.get_object(pk)
        serializer = EquipmentSerializer(equipment)
        return Response(serializer.data)

    def put(self, request, pk):
        equipment = self.get_object(pk)
        serializer = EquipmentSerializer(equipment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        equipment = self.get_object(pk)
        equipment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# views.py
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse

@ensure_csrf_cookie
def csrf_token_view(request):
    return JsonResponse({'message': 'CSRF cookie set'})


from .models import DeaconSupportRecord
from .serializers import DeaconSupportRecordSerializer


class DeaconSupportDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        return get_object_or_404(DeaconSupportRecord, pk=pk)

    def get(self, request, pk):
        record = self.get_object(pk)
        serializer = DeaconSupportRecordSerializer(record)
        return Response(serializer.data)

    def put(self, request, pk):
        record = self.get_object(pk)
        serializer = DeaconSupportRecordSerializer(record, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        record = self.get_object(pk)
        record.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
from rest_framework.generics import ListCreateAPIView

class DeaconSupportListCreateAPIView(ListCreateAPIView):
    queryset = DeaconSupportRecord.objects.all()
    serializer_class = DeaconSupportRecordSerializer
    permission_classes = [AllowAny]


from rest_framework import generics, permissions
from .models import Message, Contact
from .serializers import MessageSerializer, ContactSerializer

# Contact Views
class ContactListCreateAPIView(generics.ListCreateAPIView):
    queryset = Contact.objects.filter(is_active=True)
    serializer_class = ContactSerializer
    permission_classes = [permissions.AllowAny]

class ContactRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.AllowAny]
    
    def perform_destroy(self, instance):
        # Soft delete instead of actual deletion
        instance.is_active = False
        instance.save()

# Message Views
class MessageListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = Message.objects.all()
        # Filter messages by recipient if query param exists
        recipient = self.request.query_params.get('recipient')
        if recipient:
            queryset = queryset.filter(recipient=recipient)
        return queryset

    def perform_create(self, serializer):
        # Let the serializer handle creation and SMS sending
        serializer.save()

class MessageRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        return Message.objects.all()
    

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import UserProfile
from .serializers import UsersSerializer

class UserRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UsersSerializer
    permission_classes = [permissions.AllowAny]
    queryset = User.objects.all()
    lookup_field = 'pk'

    def get_object(self):
        obj = super().get_object()
        # Ensure profile exists
        if not hasattr(obj, 'profile'):
            UserProfile.objects.create(user=obj)
        return obj

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.pop('partial', False))
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
    

    # ==================================================

    # ================callback===========
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Message

class AfricasTalkingSMSCallbackAPIView(APIView):
    permission_classes = [permissions.AllowAny]  # No auth needed, Africa’s Talking will POST here

    def post(self, request, *args, **kwargs):
        data = request.data

        # Extract needed fields from Africa's Talking incoming message
        sender = data.get('from')  # sender phone number
        recipient = data.get('to')  # your Africastalking number
        text = data.get('text')  # message body

        # Optionally, you can validate these fields here

        # Save the message in your DB
        Message.objects.create(
            sender=None,  # or associate with a User if you want
            content=text,
            status='sent',  # Mark as sent because it's incoming message
            # you can add custom fields if your model supports them
        )

        # Respond with HTTP 200 OK so Africastalking knows you received it
        return Response({"status": "received"}, status=status.HTTP_200_OK)
# ========================timetable and other model===========
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404

from .models import Announcements, Timetable
from .serializers import AnnouncementsSerializer, TimetableSerializer

class AnnouncementsDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        return get_object_or_404(Announcements, pk=pk)

    def get(self, request, pk):
        announcement = self.get_object(pk)
        serializer = AnnouncementsSerializer(announcement)
        return Response(serializer.data)

    def put(self, request, pk):
        announcement = self.get_object(pk)
        serializer = AnnouncementsSerializer(announcement, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        announcement = self.get_object(pk)
        announcement.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class AnnouncementsListCreateAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        announcements = Announcements.objects.all()
        serializer = AnnouncementsSerializer(announcements, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = AnnouncementsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# =======================================================
# views.py
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.http import FileResponse
from .models import Timetable
from .serializers import TimetableSerializer

class TimetableListCreateAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        timetables = Timetable.objects.all()
        serializer = TimetableSerializer(timetables, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = TimetableSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TimetableDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        return get_object_or_404(Timetable, pk=pk)

    def get(self, request, pk):
        timetable = self.get_object(pk)
        serializer = TimetableSerializer(timetable)
        return Response(serializer.data)

    def put(self, request, pk):
        timetable = self.get_object(pk)
        serializer = TimetableSerializer(timetable, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        timetable = self.get_object(pk)
        if timetable.document:
            timetable.document.delete(save=False)
        timetable.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TimetableDownloadAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        timetable = get_object_or_404(Timetable, pk=pk)
        if not timetable.document:
            return Response({"error": "No document uploaded"}, status=status.HTTP_404_NOT_FOUND)
        response = FileResponse(timetable.document.open('rb'), as_attachment=True, filename=timetable.document.name.split("/")[-1])
        return response





from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Only logged-in users

    def get(self, request):
        user = request.user
        data = {
            'username': user.username,
            'email': user.email
        }
        return Response(data)

    def put(self, request):
        user = request.user
        user.username = request.data.get('username', user.username)
        user.email = request.data.get('email', user.email)
        user.save()
        return Response({'detail': 'Profile updated'})
    
    # departments

from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.generics import ListAPIView
from rest_framework.exceptions import NotFound, ValidationError
from django.db.models import Q
from .models import Department, DepartmentContent
from .serializers import DepartmentSerializer, DepartmentContentSerializer

class DepartmentsViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    permission_classes = [permissions.AllowAny]

class DepartmentContentsViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentContentSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = DepartmentContent.objects.all()
        department_name = self.request.query_params.get('department_name', None)
        department_id = self.request.query_params.get('department', None)
        
        if department_name:
            queryset = queryset.filter(
                Q(department__department_name__icontains=department_name)
            )
        
        if department_id:
            queryset = queryset.filter(department=department_id)
            
        return queryset.select_related('department')

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class DepartmentContentsByDepartment(ListAPIView):
    serializer_class = DepartmentContentSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentContent.objects.filter(department_id=department_id)

class DepartmentContentsByName(ListAPIView):
    serializer_class = DepartmentContentSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_name = self.kwargs['department_name']
        try:
            department = Department.objects.get(department_name__iexact=department_name)
            return DepartmentContent.objects.filter(department=department)
        except Department.DoesNotExist:
            raise NotFound(detail="Department not found")
        




from rest_framework import viewsets, permissions
from rest_framework.generics import ListAPIView
from rest_framework.exceptions import NotFound
from django.db.models import Q
from .models import DepartmentMembers,DepartmentAssets
from .serializers import DepartmentMembersSerializer,DepartmentAssetsSerializer

class DepartmentMembersViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentMembersSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = DepartmentMembers.objects.all()
        department_id = self.request.query_params.get('department', None)
        membership_number = self.request.query_params.get('membership_number', None)
        
        if department_id:
            queryset = queryset.filter(department=department_id)
        
        if membership_number:
            queryset = queryset.filter(membership_number__icontains=membership_number)
            
        return queryset.select_related('department')

class DepartmentMembersByDepartment(ListAPIView):
    serializer_class = DepartmentMembersSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentMembers.objects.filter(department_id=department_id)

class DepartmentMembersByMembershipNumber(ListAPIView):
    serializer_class = DepartmentMembersSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        membership_number = self.kwargs['membership_number']
        return DepartmentMembers.objects.filter(membership_number__iexact=membership_number)
    





    
from .models import DepartmentReport
from .serializers import DepartmentReportSerializer

import logging
from django.utils import timezone
from rest_framework import viewsets, permissions, serializers
from rest_framework.response import Response
from .models import DepartmentReport
from .serializers import DepartmentReportSerializer

# Set up logger
logger = logging.getLogger(__name__)

class DepartmentReportsViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentReportSerializer
    permission_classes = [permissions.AllowAny]  # Consider changing to IsAuthenticated

    def get_queryset(self):
        queryset = DepartmentReport.objects.all()
        department_id = self.request.query_params.get('department')
        report_type = self.request.query_params.get('report_type')
        
        if department_id:
            queryset = queryset.filter(department=department_id)
        if report_type:
            queryset = queryset.filter(report_type=report_type)
            
        return queryset.select_related('department')

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        partial = kwargs.pop('partial', False)
        
        # Handle file upload separately if needed
        file_upload = request.data.get('file_upload')
        if file_upload and isinstance(file_upload, str):
            # If file_upload is a string (existing file path), exclude from data
            data = request.data.copy()
            data.pop('file_upload', None)
        else:
            data = request.data

        serializer = self.get_serializer(
            instance,
            data=data,
            partial=partial
        )
        serializer.is_valid(raise_exception=True)
        
        self.perform_update(serializer)
        
        # Handle file upload after initial save if needed
        if file_upload and not isinstance(file_upload, str):
            instance.file_upload = file_upload
            instance.save()

        return Response(serializer.data)

    def perform_update(self, serializer):
        try:
            # Add any pre-save logic here
            instance = serializer.save()
            
            # Update last_modified timestamp
            instance.last_modified = timezone.now()
            instance.save()
            
            # Log the update
            user = self.request.user if self.request.user.is_authenticated else "Anonymous"
            logger.info(
                f"Report {instance.id} updated by {user}. "
                f"Changes: {serializer.validated_data}"
            )
            
        except Exception as e:
            logger.error(
                f"Error updating report {instance.id if 'instance' in locals() else 'unknown'}: {str(e)}",
                exc_info=True
            )
            raise serializers.ValidationError({
                'status': 'error',
                'message': 'Failed to save changes',
                'detail': str(e)
            })

    def partial_update(self, request, *args, **kwargs):
        """Explicitly support PATCH for partial updates"""
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)
class DepartmentReportsByDepartment(ListAPIView):
    serializer_class = DepartmentReportSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentReport.objects.filter(department_id=department_id)

class DepartmentReportsByType(ListAPIView):
    serializer_class = DepartmentReportSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        report_type = self.kwargs['report_type']
        return DepartmentReport.objects.filter(report_type=report_type)
    




class DepartmentAssetsViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentAssetsSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = DepartmentAssets.objects.all()
        department_id = self.request.query_params.get('department', None)
        AssetName = self.request.query_params.get('AssetName', None)
        
        if department_id:
            queryset = queryset.filter(department=department_id)
        
        if AssetName:
            queryset = queryset.filter(AssetName__icontains=AssetName)
           
            
        return queryset.select_related('department')

class DepartmentAssetsByDepartment(ListAPIView):
    serializer_class = DepartmentAssetsSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentAssets.objects.filter(department_id=department_id)

class DepartmentAssetsByName(ListAPIView):
    serializer_class = DepartmentMembersSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        asset_name = self.kwargs['assetName']
        return DepartmentAssets.objects.filter(asset_name__iexact=asset_name)
    




    from rest_framework import viewsets, permissions
from rest_framework.generics import ListAPIView
from .models import DepartmentOrder
from .serializers import DepartmentOrderSerializer

class DepartmentOrderViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentOrderSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        queryset = DepartmentOrder.objects.all()
        department_id = self.request.query_params.get('department', None)
        title = self.request.query_params.get('title', None)
        status = self.request.query_params.get('status', None)
        
        if department_id:
            queryset = queryset.filter(department=department_id)
        
        if title:
            queryset = queryset.filter(title__icontains=title)
            
        if status:
            queryset = queryset.filter(status__iexact=status)
            
        return queryset.select_related('department').order_by('-dateCreated')

class DepartmentOrderByDepartment(ListAPIView):
    serializer_class = DepartmentOrderSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentOrder.objects.filter(department_id=department_id).order_by('-dateCreated')

class DepartmentOrderByStatus(ListAPIView):
    serializer_class = DepartmentOrderSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        status = self.kwargs['status']
        return DepartmentOrder.objects.filter(status__iexact=status).order_by('-dateCreated')

class DepartmentOrderByTitle(ListAPIView):
    serializer_class = DepartmentOrderSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_queryset(self):
        title = self.kwargs['title']
        return DepartmentOrder.objects.filter(title__icontains=title).order_by('-dateCreated')