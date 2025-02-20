# ไฟล์ forms.py
from django import forms
from .models import Member
import bcrypt
import re
from datetime import date
from django.core.exceptions import ValidationError



class RegisterForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['Username', 'Firstname', 'Lastname', 'Password', 'Email', 'Phone', 'Birthday']
        widgets = {
            'Username': forms.TextInput(attrs={
                'placeholder': 'Username',
                'class': 'form-input',
                'maxlength': '20'  # กำหนดความยาวสูงสุดใน HTML
            }),
            'Firstname': forms.TextInput(attrs={'placeholder': 'First Name', 'class': 'form-input'}),
            'Lastname': forms.TextInput(attrs={'placeholder': 'Last Name', 'class': 'form-input'}),
            'Password': forms.PasswordInput(attrs={'placeholder': 'Password', 'class': 'form-input'}),
            'Email': forms.EmailInput(attrs={'placeholder': 'Email', 'class': 'form-input'}),
            'Phone': forms.TextInput(attrs={'placeholder': 'Telephone', 'class': 'form-input'}),
            'Birthday': forms.DateInput(attrs={
                'placeholder': 'Birth Date',
                'type': 'date',
                'class': 'form-input',
                'max': date.today().isoformat()  # ✅ แก้ไขให้ถูกต้อง
            }),
        }

    def clean_Firstname(self):
        firstname = self.cleaned_data.get('Firstname')
        if not firstname:
            raise ValidationError('กรุณากรอก First Name.')
        return firstname

    def clean_Lastname(self):
        lastname = self.cleaned_data.get('Lastname')
        if not lastname:
            raise ValidationError('กรุณากรอก Last Name.')
        return lastname

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['Username', 'Password', 'Firstname', 'Lastname', 'Email', 'Phone', 'Address']

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)

        # ตั้งค่า Email และ Username ให้อ่านได้อย่างเดียว
        self.fields['Email'].widget.attrs['readonly'] = True
        self.fields['Username'].widget.attrs['readonly'] = True

        # ✅ ไม่ดึง hash มาแสดง แต่แสดง ******** แทน
        if self.instance and self.instance.pk:
            self.initial_password = self.instance.Password  # เก็บ hash เดิมไว้ใช้ตอนบันทึก
            self.fields['Password'].initial = "********"  # ✅ แสดง ******** แทนรหัสจริง
            self.fields['Password'].widget = forms.PasswordInput(render_value=True)
        else:
            self.initial_password = None
            self.fields['Password'].widget = forms.PasswordInput(render_value=True)

    def clean_Password(self):
        password = self.cleaned_data.get('Password')

        # ✅ ถ้าผู้ใช้ไม่ได้เปลี่ยนรหัสผ่าน (ยังเป็น ********) ให้คืนค่า hash เดิม
        if password == "********":
            return self.initial_password  # ✅ คืนค่า hash เดิม ไม่ต้องตรวจสอบเงื่อนไข

        # ❌ ป้องกันรหัสผ่านเป็นค่าว่าง
        if not password:
            raise forms.ValidationError("Password cannot be empty.")

        # ✅ ตรวจสอบรูปแบบรหัสผ่านใหม่ (ถ้ามีการเปลี่ยน)
        pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            raise forms.ValidationError(
                "Password must be at least 8 characters long, include at least one uppercase letter, one number, and one special character."
            )

        # ✅ แฮชรหัสผ่านใหม่ก่อนบันทึก
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # ✅ คืนค่ารหัสผ่านที่ถูกแฮช

    def clean_Phone(self):
        phone_number = self.cleaned_data.get('Phone')
        if not phone_number or not re.match(r'^\d{10}$', phone_number):  # ตรวจสอบว่าเป็นตัวเลข 10 หลัก
            raise forms.ValidationError("Phone number must be exactly 10 digits and numeric.")
        return phone_number

    def clean_Firstname(self):
        firstname = self.cleaned_data.get('Firstname')
        if not firstname or firstname.strip() == "":
            raise forms.ValidationError("First Name cannot be empty.")
        return firstname

    def clean_Lastname(self):
        lastname = self.cleaned_data.get('Lastname')
        if not lastname or lastname.strip() == "":
            raise forms.ValidationError("Last Name cannot be empty.")
        return lastname

    def clean_Address(self):
        address = self.cleaned_data.get('Address')
        if not address or address.strip() == "":
            raise forms.ValidationError("Address cannot be empty.")
        return address