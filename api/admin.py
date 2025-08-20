from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from django.utils.html import format_html
from rangefilter.filters import DateRangeFilter

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'phoneNumber', 'role', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_active')
    search_fields = ('username', 'email', 'phoneNumber')
    fieldsets = UserAdmin.fieldsets + (('Additional Info', {'fields': ('phoneNumber', 'role')}),)

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'amount', 'challenge_type', 'date', 'status')
    list_filter = ('status', 'challenge_type', ('date', DateRangeFilter))
    search_fields = ('name', 'description')
    list_editable = ('status',)

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'created_at')
    list_filter = (('created_at', DateRangeFilter),)
    search_fields = ('name', 'email', 'content')

@admin.register(UserUpdate)
class UserUpdateAdmin(admin.ModelAdmin):
    list_display = ('user', 'role')
    list_filter = ('role',)
    autocomplete_fields = ('user',)

@admin.register(Equipment)
class EquipmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'total_quantity', 'functional', 'broken', 'status', 'action')  # Fixed: added 'action'
    list_filter = ('status', 'action')
    search_fields = ('name', 'need')
    list_editable = ('status', 'action')
    readonly_fields = ('broken_percentage',)
    
    def broken_percentage(self, obj):
        if obj.total_quantity > 0:
            percentage = (obj.broken / obj.total_quantity) * 100
            return f"{percentage:.1f}%"
        return "0%"
    broken_percentage.short_description = 'Broken Percentage'

@admin.register(DeaconSupportRecord)
class DeaconSupportRecordAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'amount', 'challenge_type', 'date', 'status')
    list_filter = ('status', 'challenge_type', ('date', DateRangeFilter))
    list_editable = ('status',)

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'phone_number', 'email', 'role', 'is_active')
    list_filter = ('role', 'is_active')
    list_editable = ('is_active', 'role')

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('content_preview', 'status', 'created_at')
    list_filter = ('status', ('created_at', DateRangeFilter))
    
    def content_preview(self, obj):
        return obj.content[:30] + '...' if obj.content else 'No content'

@admin.register(Announcements)
class AnnouncementsAdmin(admin.ModelAdmin):
    list_display = ('title', 'date')
    list_filter = (('date', DateRangeFilter),)
    search_fields = ('title', 'content')

@admin.register(Timetable)
class TimetableAdmin(admin.ModelAdmin):
    list_display = ('title', 'date', 'document_link')
    list_filter = (('date', DateRangeFilter),)
    search_fields = ('title',)
    
    def document_link(self, obj):
        if obj.document:
            return format_html('<a href="{}" target="_blank">View</a>', obj.document.url)
        return "No document"

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('department_name', 'date_created')
    search_fields = ('department_name',)

@admin.register(DepartmentContent)
class DepartmentContentAdmin(admin.ModelAdmin):
    list_display = ('department', 'year_order', 'implementation_status', 'cost')
    list_filter = ('implementation_status', 'department')
    list_editable = ('implementation_status',)
    autocomplete_fields = ('department',)

@admin.register(DepartmentMembers)
class DepartmentMembersAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'department', 'mobile_number', 'baptism_status')
    list_filter = ('department', 'baptism_status')
    autocomplete_fields = ('department',)

@admin.register(DepartmentReport)
class DepartmentReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'department', 'report_type', 'report_date')
    list_filter = ('report_type', 'department')
    autocomplete_fields = ('department',)

@admin.register(DepartmentAssets)
class DepartmentAssetsAdmin(admin.ModelAdmin):
    list_display = ('AssetName', 'department', 'totalNumberOfAssets', 'isRequired')
    list_filter = ('department', 'isRequired')
    list_editable = ('isRequired',)
    autocomplete_fields = ('department',)

@admin.register(DepartmentOrder)
class DepartmentOrderAdmin(admin.ModelAdmin):
    list_display = ('title', 'department', 'dateCreated', 'status')
    list_filter = ('status', 'department')
    list_editable = ('status',)
    autocomplete_fields = ('department',)

@admin.register(HeaderImage)
class HeaderImageAdmin(admin.ModelAdmin):
    list_display = ('title', 'description_preview', 'image_preview', 'created_at')
    list_filter = (('created_at', DateRangeFilter),)
    search_fields = ('title', 'description')
    readonly_fields = ('created_at', 'updated_at', 'image_preview')
    
    def description_preview(self, obj):
        return obj.description[:50] + '...' if obj.description else 'No description'
    description_preview.short_description = 'Description Preview'
    
    def image_preview(self, obj):
        if obj.image:
            return format_html('<img src="{}" style="max-height: 100px; max-width: 150px;" />', obj.image.url)
        return "No image"
    image_preview.short_description = 'Image Preview'
    
    fieldsets = (
        (None, {
            'fields': ('title', 'description', 'image', 'image_preview')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


# Admin site configuration
admin.site.site_header = "Bahi Church Management System"
admin.site.site_title = "b_CMS Admin"
admin.site.index_title = "Welcome to b_CMS Administration"