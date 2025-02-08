from django import forms
from myapp.models import Member

class RegisterForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['Username', 'Fname', 'Lname', 'Psw', 'Email', 'Tel', 'Address', 'Bdate']
        widgets = {
            'Bdate': forms.DateInput(attrs={'type': 'date'})
        }
