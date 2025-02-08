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
        fields = ['Username', 'Firstname', 'Lastname', 'Password', 'Email', 'Phone', 'Address', 'Birthday']
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
            'Address': forms.TextInput(attrs={'placeholder': 'Address', 'class': 'form-input'}),
            'Birthday': forms.DateInput(attrs={
                'placeholder': 'Birth Date',
                'type': 'date',
                'class': 'form-input',
                'max': date.today().isoformat()  # กำหนดวันที่สูงสุดเป็นปัจจุบัน
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

    def clean_Address(self):
        address = self.cleaned_data.get('Address')
        if not address:
            raise ValidationError('กรุณากรอก Address.')
        return address

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['Username', 'Password', 'Firstname', 'Lastname', 'Email', 'Phone', 'Address']

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)
        self.fields['Email'].widget.attrs['readonly'] = True
        self.fields['Username'].widget.attrs['readonly'] = True
        self.fields['Password'].widget = forms.PasswordInput(render_value=True)

    def clean_Password(self):
        password = self.cleaned_data.get('Password')

        # ตรวจสอบว่ารหัสผ่านไม่เป็นค่าว่าง
        if not password:
            raise forms.ValidationError("Password cannot be empty.")

        # ตรวจสอบรูปแบบรหัสผ่าน
        pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            raise forms.ValidationError(
                "Password must be at least 8 characters long, include at least one uppercase letter, one number, and one special character."
            )

        # แฮชรหัสผ่านด้วย bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')  # คืนค่ารหัสผ่านที่ถูกแฮช
    
    def clean_Phone(self):
        phone_number = self.cleaned_data.get('Phone')
        if not phone_number or not re.match(r'^\d{10}$', phone_number):  # ตรวจสอบว่าเป็นตัวเลข 10 หลัก
            raise forms.ValidationError("Phone number must be exactly 10 digits and numeric.")
        return phone_number