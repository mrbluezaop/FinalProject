from django.db import models
from django.utils.timezone import now

class Member(models.Model):
    Customer_ID = models.AutoField(primary_key=True)
    Username = models.CharField(max_length=20, unique=True)
    Firstname = models.CharField(max_length=100, blank=True, null=True)
    Lastname = models.CharField(max_length=100, blank=True, null=True)
    Password = models.CharField(max_length=100, blank=True, null=True)
    Email = models.EmailField(max_length=100, unique=True)
    Phone = models.CharField(max_length=10, blank=True, null=True)
    Address = models.CharField(max_length=100, blank=True, null=True)
    Birthday = models.DateField(null=True, blank=True)
    joined_date = models.DateTimeField(auto_now_add=True)

class HireforAdmin(models.Model):
    HireA_ID = models.AutoField(primary_key=True)
    Width = models.FloatField(verbose_name="Width (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Length = models.FloatField(verbose_name="Length (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Height = models.FloatField(verbose_name="Height (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Type = models.CharField(max_length=100)  # VARCHAR2 (100)
    Budget = models.CharField(max_length=150)  # VARCHAR2 (150)
    Location = models.CharField(max_length=150)  # VARCHAR2 (150)

class Hire(models.Model):
    STATUS_CHOICES = [
        ('in_progress', 'อยู่ระหว่างการทำ'),
        ('completed', 'ทำเสร็จสิ้นแล้ว'),
        ('waiting_confirmation', 'รอการยืนยัน'),
    ]
    Hire_ID = models.AutoField(primary_key=True)  # Primary Key
    Customer_ID = models.ForeignKey(Member, on_delete=models.CASCADE)  # Foreign Key
    Width = models.FloatField(verbose_name="Width (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Length = models.FloatField(verbose_name="Length (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Height = models.FloatField(verbose_name="Height (m.)")  # FLOAT (ไม่ต้องมี max_length)
    Type = models.CharField(max_length=100)  # VARCHAR2 (100)
    Budget = models.FloatField(max_length=150)  # VARCHAR2 (150)
    Location = models.CharField(max_length=150)  # VARCHAR2 (150)
    Dateofhire = models.DateTimeField(default=now)  # กำหนดวันที่สร้างเป็นเวลาปัจจุบัน
    Status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='waiting_confirmation', verbose_name="Status")
 
    def __str__(self):
        return f"Hire {self.Hire_ID} for Customer {self.Customer_ID}"
    
class PredictHire(models.Model):
    Predict_ID = models.AutoField(primary_key=True)
    HireC_ID = models.OneToOneField(Hire, on_delete=models.CASCADE)  # เชื่อมกับ HireforCustomer
    Width = models.FloatField()
    Length = models.FloatField()
    Height = models.FloatField()
    Type = models.CharField(max_length=100)
    Budget = models.CharField(max_length=150)
    Area = models.FloatField(verbose_name="Area")
    Wood = models.IntegerField(verbose_name="Wood (pc.)")
    Lighting = models.IntegerField(verbose_name="Lighting (pc.)")
    Nail = models.IntegerField(verbose_name="Nail (box.)")
    Table = models.IntegerField(verbose_name="Table")
    Chair = models.IntegerField(verbose_name="Chair")

    def __str__(self):
        return f"Predict for Hire {self.HireC_ID.Hire_ID}"