from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver


from django.db import models

class User(AbstractUser):
    phoneNumber = models.CharField(max_length=20, blank=True)
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'Regular User'),
        ('manager', 'Manager'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    
    def __str__(self):
        return self.username

class Service(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    assisted_people = models.PositiveIntegerField(default=0)
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # Adjust max_digits as needed
    prayed_for = models.PositiveIntegerField(default=0)
    challenge_type = models.CharField(max_length=100)
    people_prayed_for = models.PositiveIntegerField(default=0)
    date = models.DateField()
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return self.name
# =================COMMENTS==========
class Comment(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.email}"


# ===========================
class UserUpdate(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='role_update')
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES, default='user')

    def __str__(self):
        return f"{self.user.username} - {self.role}"

class Equipment(models.Model):
    name = models.CharField("Jina la Vifaa", max_length=255)
    total_quantity = models.PositiveIntegerField("Idadi Jumla", default=0)
    
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('unavailable', 'Unavailable'),
        ('maintenance', 'Under Maintenance'),
    ]
    status = models.CharField("Hali", max_length=20, choices=STATUS_CHOICES, default='available')
    
    functional = models.PositiveIntegerField("Imara", default=0)
    broken = models.PositiveIntegerField("Vibovu", default=0)
    
    need = models.CharField("Uhitaji", max_length=255, blank=True)
    need_quantity = models.PositiveIntegerField("Idadi ya Uhitaji", default=0)
    
    cost = models.DecimalField("Gharama", max_digits=12, decimal_places=2, default=0.00)
    
    ACTION_CHOICES = [
        ('repair', 'Repair'),
        ('replace', 'Replace'),
        ('order', 'Order More'),
        ('none', 'None'),
    ]
    action = models.CharField("Hatua", max_length=20, choices=ACTION_CHOICES, default='none')
    
    def __str__(self):
        return self.name




class DeaconSupportRecord(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('ongoing', 'Ongoing'),
    ]

    full_name = models.CharField("Jina kamili", max_length=200)
    description = models.TextField("Maelezo", blank=True)
    assisted_people = models.PositiveIntegerField("Waliosaidiwa", default=0)
    amount = models.DecimalField("Kiasi", max_digits=10, decimal_places=2, default=0.00)
    prayed_for = models.TextField("majina ya Ulio waombea", blank=True)
    challenge_type = models.CharField("Aina ya changamoto", max_length=255)
    people_prayed_for = models.PositiveIntegerField("idadi ya ulio waombeasource ", default=0)
    date = models.DateField("Tarehe")
    status = models.CharField("Hali", max_length=50, choices=STATUS_CHOICES, default='pending')
    action = models.TextField("Hatua", blank=True)

    def __str__(self):
        return f"{self.full_name} - {self.date}"


from django.db import models
from twilio.rest import Client

# Create your models here.


from django.db import models
from django.contrib.auth import get_user_model
from twilio.rest import Client
from django.conf import settings

User = get_user_model()

from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator

User = get_user_model()

class Contact(models.Model):
    phone_regex = RegexValidator(
        regex=r'^\+?255?\d{9,15}$',
        message="Phone number must be in format: '+255'"
    )
    phone_number = models.CharField(
        validators=[phone_regex],
        max_length=17,
        unique=True,
        null=False
    )
    
    name = models.CharField(max_length=100, blank=True)
    email=models.EmailField(max_length=100, null=True)

    role = models.CharField(
        max_length=40,
        choices=[
            ('user', 'User'),
            ('Admin', 'Admin'),
            ('staff', 'staff'),
            
        ],
        default='user'
    )
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} ({self.phone_number})"

from django.db import models
from twilio.rest import Client
from django.conf import settings
import africastalking

from django.db import models
from django.conf import settings
import africastalking

class Message(models.Model):
    sender = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    # Remove recipient FK since we're sending to all contacts
    content = models.TextField(null=True)
    status = models.CharField(
        max_length=40,
        choices=[
            ('pending', 'Pending'),
            ('sent', 'Sent'),
            ('failed', 'Failed'),
            ('message sent successfully', 'message  Sent')
        ],
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    
    def __str__(self):
        return f"Bulk message: {self.content[:20]}..."
    
    def send_bulk_sms(self):
        from .models import Contact  # Avoid circular imports

        # Initialize Africa's Talking with your credentials
        username = "bahi"  # <-- replace with your Africa's Talking username
        api_key = "atsk_6d6d65acfca1d589d8ed7b11d143b017c32867e7b7bc1583ac6bdb677901351c1f1e317a"  # Your API key

        africastalking.initialize(username, api_key)
        sms = africastalking.SMS

        try:
            active_contacts = Contact.objects.filter(is_active=True)
            phone_numbers = [contact.phone_number for contact in active_contacts]

            if not phone_numbers:
                self.status = 'failed'
                self.save()
                return False

            # Africa's Talking send method expects a list of numbers
            response = sms.send(self.content, phone_numbers)

            # You can parse the response to see how many succeeded
            # For simplicity, let's assume if response is returned, it's success
            self.status = 'message sent successfully to mass'
            self.save()
            return True

        except Exception as e:
            # You can log e if you want
            self.status = 'failed'
            self.save()
            return False
# ==========================Announcements=============
class Announcements(models.Model):
    date=models.DateField(auto_now_add=True,null=True)
    title=models.CharField(max_length=50,null=True)
    content=models.TextField(max_length=300,null=True)


    def __str__(self):
        return self.title
    
# =========================Timetable
class Timetable(models.Model):
    date=models.DateField(auto_now_add=True,null=True)
    title=models.CharField(max_length=50,null=True)
    document=models.FileField(upload_to='timetable/%Y/%m/%d/', blank=True, null=True)
    
    def __str__(self):
        return self.document
    def __str__(self):
        try:
            # Try to return a string representation
            if hasattr(self, 'name'):
                return str(self.name)
            elif hasattr(self, 'title'):
                return str(self.title)
            else:
                return f"Timetable {self.id}"
        except:
            return f"Timetable {self.id}"
    

  



#   departments
from django.db import models


from django.db import models
from django.core.validators import MinLengthValidator

class Department(models.Model):  # Changed to singular name (best practice)
    department_name = models.CharField(
        max_length=255,
        unique=True,
        validators=[MinLengthValidator(2)],  # Ensure at least 2 characters
        help_text="Name of the department (must be unique)",
        error_messages={
            'unique': "A department with this name already exists.",
        }
    )
    date_created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)  # Added to track modifications

    class Meta:
        verbose_name = "Department"  # Singular name in admin
        verbose_name_plural = "Departments"  # Plural name in admin
        ordering = ['department_name']  # Default ordering

    def __str__(self):
        return self.department_name

    def clean(self):
        # Optional: Add any custom validation logic here
        self.department_name = self.department_name.strip()  # Remove leading/trailing whitespace


class DepartmentContent(models.Model):  # Changed to singular name (best practice)
    IMPLEMENTATION_STATUS_CHOICES = [
        ('completed', 'Completed'),
        ('in_progress', 'In Progress'),
        ('incomplete', 'Incomplete'),
    ]

    department = models.ForeignKey(
        Department,  # Updated to match new model name
        on_delete=models.CASCADE,
        related_name="contents",
        verbose_name="Department"
    )
    year_order = models.PositiveIntegerField(
        verbose_name="Year",
        help_text="The year this content is associated with"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)  # Added to track modifications
    short_description = models.TextField(
        verbose_name="Description",
        validators=[MinLengthValidator(10)]  # Ensure meaningful descriptions
    )
    cost = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        verbose_name="Estimated Cost",
        help_text="Estimated cost in local currency"
    )
    implementation_status = models.CharField(
        max_length=20,
        choices=IMPLEMENTATION_STATUS_CHOICES,
        default='incomplete',
        verbose_name="Status"
    )

    class Meta:
        verbose_name = "Department Content"  # Singular name in admin
        verbose_name_plural = "Department Contents"  # Plural name in admin
        ordering = ['-year_order', 'department']  # Default ordering
        unique_together = ['department', 'year_order']  # Prevent duplicate year entries per department

    def __str__(self):
        return f"{self.department.department_name} - {self.year_order} ({self.get_implementation_status_display()})"

    def clean(self):
        # Optional: Add any custom validation logic here
        self.short_description = self.short_description.strip()


class DepartmentMembers(models.Model):
    BAPTISM_STATUS_CHOICES = [
        ('baptized', 'Baptized'),
        ('not_baptized', 'Not Baptized'),
    ]
    
    MARITAL_STATUS_CHOICES = [
        ('in_marriage', 'In Marriage'),
        ('not_in_marriage', 'Not In Marriage'),
        ('in_relationship', 'In Relationship'),
    ]

    department = models.ForeignKey(
        Department,
        on_delete=models.CASCADE,
        related_name="members",
        verbose_name="Department"
    )
    full_name = models.CharField(
        max_length=100,
        verbose_name="Full Name",
        validators=[MinLengthValidator(3)]
    )
    mobile_number = models.CharField(
        max_length=20,
        verbose_name="Mobile Number",
        blank=True,
        null=True
    )
    email = models.EmailField(
        verbose_name="Email Address",
        blank=True,
        null=True
    )
    baptism_status = models.CharField(
        max_length=20,
        choices=BAPTISM_STATUS_CHOICES,
        verbose_name="Baptism Status"
    )
    marital_status = models.CharField(
        max_length=20,
        choices=MARITAL_STATUS_CHOICES,
        verbose_name="Marital Status"
    )
    membership_number = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="Membership Number",
        help_text="Unique identifier for the member"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Department Member"
        verbose_name_plural = "Department Members"
        ordering = ['full_name', 'department']
        constraints = [
            models.UniqueConstraint(
                fields=['department', 'membership_number'],
                name='unique_department_membership'
            )
        ]

    def __str__(self):
        return f"{self.full_name} ({self.membership_number}) - {self.department.department_name}"

    def clean(self):
        # Clean and validate data before saving
        self.full_name = self.full_name.strip()
        if self.mobile_number:
            self.mobile_number = self.mobile_number.strip()
        if self.email:
            self.email = self.email.strip().lower()
        self.membership_number = self.membership_number.strip()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)






class DepartmentReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('annual', 'Annual'),
        ('special', 'Special'),
    ]

    department = models.ForeignKey(
        Department,
        on_delete=models.CASCADE,
        related_name="reports",
        verbose_name="Department"
    )
    title = models.CharField(
        max_length=200,
        verbose_name="Report Title"
    )
    report_type = models.CharField(
        max_length=20,
        choices=REPORT_TYPE_CHOICES,
        verbose_name="Report Type"
    )
    report_date = models.DateField(
        verbose_name="Report Date"
    )
    description = models.TextField(
        verbose_name="Description",
        blank=True,
        null=True
    )
    file_upload = models.FileField(
        upload_to='department_reports/',
        verbose_name="File Upload",
        blank=True,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Department Report"
        verbose_name_plural = "Department Reports"
        ordering = ['-report_date', 'department']
        indexes = [
            models.Index(fields=['department', 'report_date']),
        ]

    def __str__(self):
        return f"{self.title} - {self.department.department_name} ({self.get_report_type_display()})"
    




class DepartmentAssets(models.Model):
    
    
    SELECT_CHOICES = [
        ('is required', 'is required'),
        ('not required', 'not required'),
        ]

    department = models.ForeignKey(
        Department,
        on_delete=models.CASCADE,
        related_name="assets",
        verbose_name="Department"
    )
    title = models.CharField(
        max_length=100,
        verbose_name="title",
        validators=[MinLengthValidator(3)]
    )
    dateOfAnalysis = models.DateField(
        
        verbose_name="date of analysis",
        blank=True,
        null=True
    )
    AssetName = models.CharField(
        verbose_name="asset name",
        blank=True,
        null=True,
        max_length=20
    )
    totalNumberOfAssets = models.IntegerField(
        verbose_name="total number of assets"
    )
    abledAssetsNumber = models.IntegerField(
        verbose_name="total number of abled assets"
    )
    disabledAssetsNumber = models.IntegerField(

        verbose_name="total number of disabled assets"
        
    )
    isRequired=models.CharField(
        max_length=20,
        null=True,
        choices=SELECT_CHOICES,
        verbose_name="is required?"

    )
    perCost=models.IntegerField(
        null=True,
        verbose_name="cost per asset"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Department asset"
        verbose_name_plural = "Department Assets"
        ordering = ['title', 'department']
        indexes = [
            models.Index(fields=['department', 'AssetName']),
        ]

    def __str__(self):
        return f"{self.AssetName} ({self.totalNumberOfAssets}) - {self.department.abledAssetsNumber}"

    def clean(self):
        # Clean and validate data before saving
        self.AssetName = self.AssetName.strip()
        if self.totalNumberOfAssets:
            self.totalNumberOfAssets = self.totalNumberOfAssets.bit_length()
        

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)




from django.db import models
from django.core.validators import MinLengthValidator
from .models import Department  # Assuming Department model exists

class DepartmentOrder(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    department = models.ForeignKey(
        Department,
        on_delete=models.CASCADE,
        related_name="orders",
        verbose_name="Department"
    )
    title = models.CharField(
        max_length=100,
        verbose_name="Order Title",
        validators=[MinLengthValidator(3)]
    )
    dateCreated = models.DateField(
        verbose_name="Date Created",
        auto_now_add=True
    )
    dateToImplement = models.DateField(
        verbose_name="Implementation Deadline"
    )
    howToImplement = models.TextField(
        verbose_name="Implementation Instructions"
    )
    Requirements = models.TextField(
        verbose_name="Requirements"
    )
    costToImplement = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name="Implementation Cost"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        verbose_name="Order Status"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Department Order"
        verbose_name_plural = "Department Orders"
        ordering = ['-dateCreated']
        indexes = [
            models.Index(fields=['department', 'status']),
        ]

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def clean(self):
        # Custom validation
        if self.dateToImplement and self.dateCreated:
            if self.dateToImplement < self.dateCreated:
                return 
        self.title = self.title.strip()





# ======================HEADER MODEL=======================
from django.db import models

class HeaderImage(models.Model):
    title = models.CharField(max_length=200, verbose_name="Title")
    description = models.TextField(blank=True, verbose_name="Description")
    image = models.ImageField(
        upload_to='header_images/',
        verbose_name="Header Image",
        help_text="Upload a header image"
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    class Meta:
        verbose_name = "Header Image"
        verbose_name_plural = "Header Images"
        ordering = ['-created_at']

    def __str__(self):
        return self.title