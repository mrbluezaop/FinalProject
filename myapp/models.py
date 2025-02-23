from django.db import models
from django.utils.timezone import now
from django.core.exceptions import ValidationError

class Member(models.Model):
    Customer_ID = models.AutoField(primary_key=True)
    Username = models.CharField(max_length=20, unique=True)
    Firstname = models.CharField(max_length=100, blank=True, null=True)
    Lastname = models.CharField(max_length=100, blank=True, null=True)
    Password = models.CharField(max_length=100, blank=True, null=True)
    Email = models.EmailField(max_length=100, unique=True)
    Phone = models.CharField(max_length=10, blank=True, null=True)

    # ✅ บันทึกที่อยู่ที่รวมแล้ว
    Address = models.CharField(max_length=255, blank=True, null=True)

    Birthday = models.DateField(null=True, blank=True)
    joined_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.Username

class HireforAdmin(models.Model):
    STATUS_CHOICES = [
        ('in_progress', 'อยู่ระหว่างการทำ'),
        ('completed', 'ทำเสร็จสิ้นแล้ว'),
    ]
    HireA_ID = models.AutoField(primary_key=True)
    Width = models.FloatField(verbose_name="Width (m.)")
    Length = models.FloatField(verbose_name="Length (m.)")
    Height = models.FloatField(verbose_name="Height (m.)")
    Type = models.CharField(max_length=100)
    Budget = models.CharField(max_length=150)
    Location = models.CharField(max_length=150, default="-")
    Dateofhire = models.DateTimeField(default=now)
    Status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='in_progress', verbose_name="Status")

class Hire(models.Model):
    STATUS_CHOICES = [
        ('in_progress', 'อยู่ระหว่างการทำ'),
        ('completed', 'ทำเสร็จสิ้นแล้ว'),
        ('waiting_confirmation', 'รอการยืนยัน'),
    ]
    Hire_ID = models.AutoField(primary_key=True)
    Customer_ID = models.ForeignKey(Member, on_delete=models.CASCADE, related_name="hires")
    Width = models.FloatField(verbose_name="Width (m.)")
    Length = models.FloatField(verbose_name="Length (m.)")
    Height = models.FloatField(verbose_name="Height (m.)")
    Type = models.CharField(max_length=100)
    Budget = models.FloatField()
    Location = models.CharField(max_length=150, default="-")
    Dateofhire = models.DateTimeField(default=now)
    Status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='waiting_confirmation', verbose_name="Status")
    QC_Number = models.IntegerField(unique=True)

    def save(self, *args, **kwargs):
        if not self.QC_Number:
            last_hire = Hire.objects.order_by('-QC_Number').first()
            if last_hire:
                self.QC_Number = last_hire.QC_Number + 1
            else:
                self.QC_Number = 1 

        super().save(*args, **kwargs)

    def formatted_number(self):
        """ แสดงหมายเลขเป็น 5 หลัก เช่น 00001, 00002 """
        return str(self.QC_Number).zfill(5)

    def __str__(self):
        return f"Hire {self.Hire_ID} for Customer {self.Customer_ID}"

class PredictHire(models.Model):
    Predict_ID = models.AutoField(primary_key=True)
    HireC_ID = models.ForeignKey(
        "Hire", on_delete=models.CASCADE, null=True, blank=True, related_name="predict_hires"
    )
    HireA_ID = models.ForeignKey(
        "HireforAdmin", on_delete=models.CASCADE, null=True, blank=True, related_name="predict_hires"
    )

    Width = models.FloatField()
    Length = models.FloatField()
    Height = models.FloatField()
    Type = models.CharField(max_length=100)
    Budget = models.DecimalField(max_digits=15, decimal_places=2)
    Area = models.FloatField(verbose_name="Area")
    Wood = models.IntegerField(verbose_name="Wood (pc.)", default=0)
    Paint = models.IntegerField(verbose_name="Paint (buck.)", default=0)
    Lighting = models.IntegerField(verbose_name="Lighting (pc.)", default=0)
    Nail = models.IntegerField(verbose_name="Nail (box.)", default=0)
    Table = models.IntegerField(verbose_name="Table", default=0)
    Chair = models.IntegerField(verbose_name="Chair", default=0)
    Dateofhire = models.DateTimeField(default=now)

    def clean(self):
        """✅ ตรวจสอบว่าต้องมีค่าใน HireC_ID หรือ HireA_ID อย่างใดอย่างหนึ่ง"""
        if not self.HireC_ID and not self.HireA_ID:
            raise ValidationError("ต้องมีค่าใน HireC_ID หรือ HireA_ID อย่างน้อยหนึ่งฟิลด์")
        if self.HireC_ID and self.HireA_ID:
            raise ValidationError("ต้องเลือกเพียง HireC_ID หรือ HireA_ID เท่านั้น ห้ามมีค่าทั้งสอง")

    def save(self, *args, **kwargs):
        """✅ กำหนดค่า Dateofhire ตาม HireC_ID หรือ HireA_ID"""
        if self.HireC_ID:
            self.Dateofhire = self.HireC_ID.Dateofhire
        elif self.HireA_ID:
            self.Dateofhire = self.HireA_ID.Dateofhire
        super().save(*args, **kwargs)

    def __str__(self):
        if self.HireC_ID:
            return f"Predict for Hire (Customer) {self.HireC_ID.Hire_ID}"
        elif self.HireA_ID:
            return f"Predict for Hire (Admin) {self.HireA_ID.HireA_ID}"
        return "Predict for Unknown Hire"

class Resource(models.Model):
    Resource_ID = models.AutoField(primary_key=True)
    Predict_ID = models.OneToOneField("PredictHire", on_delete=models.CASCADE, related_name="resource")
    Width = models.FloatField()
    Length = models.FloatField()
    Height = models.FloatField()
    Type = models.CharField(max_length=100)
    Location = models.CharField(max_length=150, null=True, blank=True)
    Budget = models.DecimalField(max_digits=15, decimal_places=2)
    Wood_P = models.IntegerField(verbose_name="Wood (pc.) Predict", default=0)
    Paint_P = models.IntegerField(verbose_name="Paint (buck.) Predict", default=0)
    Lighting_P = models.IntegerField(verbose_name="Lighting (pc.) Predict", default=0)
    Nail_P = models.IntegerField(verbose_name="Nail (box.) Predict", default=0)
    Table_P = models.IntegerField(verbose_name="Table Predict", default=0)
    Chair_P = models.IntegerField(verbose_name="Chair Predict", default=0)
    Wood = models.IntegerField(verbose_name="Wood (pc.) Actual", default=0)
    Paint = models.IntegerField(verbose_name="Paint (buck.)", default=0)
    Lighting = models.IntegerField(verbose_name="Lighting (pc.) Actual", default=0)
    Nail = models.IntegerField(verbose_name="Nail (box.) Actual", default=0)
    Table = models.IntegerField(verbose_name="Table Actual", default=0)
    Chair = models.IntegerField(verbose_name="Chair Actual", default=0)
    Dateofhire = models.DateTimeField(null=True, blank=True)  # ✅ อนุญาตให้เป็น null และ blank ได้
    DateSuccess = models.DateTimeField(default=now)

    def save(self, *args, **kwargs):
        """✅ กำหนดค่า Dateofhire จาก PredictHire"""
        if self.Predict_ID and self.Predict_ID.Dateofhire:
            self.Dateofhire = self.Predict_ID.Dateofhire
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Resource for PredictHire {self.Predict_ID.Predict_ID if self.Predict_ID else 'Unknown'}"

