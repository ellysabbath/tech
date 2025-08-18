from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializers(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    
    def update(self, instance, validated_data):
        # Update username and email if provided
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)

        # Update password if provided
        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)
        instance.save()
        return instance
    
# =====================================
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phoneNumber', 'role']

class UsersSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    status = serializers.BooleanField(source='is_active', required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'profile', 'status']
        extra_kwargs = {
            'email': {'required': True}
        }

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', {})
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email']
        )
        UserProfile.objects.create(user=user, **profile_data)
        return user

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        
        # Update User fields
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        
        # Update is_active if provided
        if 'is_active' in validated_data:
            instance.is_active = validated_data['is_active']
        
        instance.save()
        
        # Get or create profile
        profile, created = UserProfile.objects.get_or_create(user=instance)
        
        # Update profile fields
        for attr, value in profile_data.items():
            setattr(profile, attr, value)
        profile.save()
        
        return instance
    # ===================================================
    



from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)




from rest_framework import serializers
from .models import Service, Equipment

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'


class EquipmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Equipment
        fields = '__all__'

from .models import DeaconSupportRecord

class DeaconSupportRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeaconSupportRecord
        fields = '__all__'
from rest_framework import serializers
from .models import Message
from django.contrib.auth import get_user_model

User = get_user_model()

from rest_framework import serializers
from .models import Contact, Message

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['id', 'phone_number', 'name', 'is_active','email','role']

class MessageSerializer(serializers.ModelSerializer):
    # Remove the recipient field since we're sending to all contacts
    class Meta:
        model = Message
        fields = ['id', 'sender', 'content', 'status', 'created_at']
        read_only_fields = ['status', 'created_at', 'sender']
    
    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['sender'] = request.user if request.user.is_authenticated else None
        
        message = Message.objects.create(**validated_data)
        success = message.send_bulk_sms()  # Changed from send_sms() to send_bulk_sms()
        
        if not success:
            raise serializers.ValidationError(
                "Failed to send to some or all recipients. Check message status."
            )
            
        return message
    
    # ==================================the rest models===============
    from rest_framework import serializers
from .models import Announcements, Timetable

class AnnouncementsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcements
        fields = ['id', 'date', 'title', 'content']

from rest_framework import serializers
from .models import Timetable

class TimetableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timetable
        fields = ['id', 'date', 'title', 'document']
        read_only_fields = ['date']

    # Optional: validate file size/type here if needed
from rest_framework import serializers
from .models import Department, DepartmentContent  # Updated import names

class DepartmentSerializer(serializers.ModelSerializer):  # Changed to singular
    class Meta:
        model = Department  # Updated model reference
        fields = ['id', 'department_name', 'date_created', 'last_modified']  # Added last_modified


class DepartmentContentSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(
        source='department.department_name', 
        read_only=True
    )
    
    class Meta:
        model = DepartmentContent
        fields = '__all__'
        extra_kwargs = {
            'department': {'write_only': True}  # Optional: hide in responses
        }

from rest_framework import serializers
from .models import DepartmentMembers

class DepartmentMembersSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.department_name', read_only=True)
    
    class Meta:
        model = DepartmentMembers
        fields = [
            'id',
            'department',
            'department_name',
            'full_name',
            'mobile_number',
            'email',
            'baptism_status',
            'marital_status',
            'membership_number',
            'created_at',
            'last_modified'
        ]
        extra_kwargs = {
            'department': {'required': True},
            'membership_number': {'required': True}
        }


from .models import DepartmentReport
class DepartmentReportSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.department_name', read_only=True)
    
    class Meta:
        model = DepartmentReport
        fields = [
            'id',
            'department',
            'department_name',
            'title',
            'report_type',
            'report_date',
            'description',
            'file_upload',
            'created_at',
            'last_modified'
        ]
        extra_kwargs = {
            'department': {'required': True},
            'title': {'required': True},
            'report_type': {'required': True},
            'report_date': {'required': True}
        }

    def validate(self, data):
        errors = {}
        if 'department' not in data:
            errors['department'] = "This field is required"
        if 'title' not in data:
            errors['title'] = "This field is required"
        if 'report_type' not in data:
            errors['report_type'] = "This field is required"
        if 'report_date' not in data:
            errors['report_date'] = "This field is required"
        
        if errors:
            raise serializers.ValidationError(errors)
        
        return data
    

from .models import DepartmentAssets
class DepartmentAssetsSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.department_name', read_only=True)
    
    class Meta:
        model = DepartmentAssets
        fields = "__all__"
        extra_kwargs = {
            'department': {'required': True},
            'totalNumberOfAssets': {'required': True}
        }





from .models import DepartmentOrder
from rest_framework import serializers
from .models import DepartmentOrder

class DepartmentOrderSerializer(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.department_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = DepartmentOrder
        fields = [
            'id',
            'department',
            'department_name',
            'title',
            'dateCreated',
            'dateToImplement',
            'howToImplement',
            'Requirements',
            'costToImplement',
            'status',
            'status_display',
            'created_at',
            'last_modified'
        ]
        extra_kwargs = {
            'department': {'required': True},
            'title': {
                'required': True,
                'min_length': 3,
                'error_messages': {
                    'min_length': 'Title must be at least 3 characters long.'
                }
            },
            'dateToImplement': {'required': True},
            'howToImplement': {'required': True},
            'Requirements': {'required': True},
            'costToImplement': {
                'required': True,
                'min_value': 0,
                'error_messages': {
                    'min_value': 'Cost cannot be negative.'
                }
            }
        }

    def validate(self, data):
        """
        Custom validation for order data
        """
        if 'dateToImplement' in data and 'dateCreated' in data:
            if data['dateToImplement'] < data['dateCreated']:
                raise serializers.ValidationError(
                    "Implementation date cannot be before creation date"
                )
        return data