from django.db import models

# Create your models here.
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