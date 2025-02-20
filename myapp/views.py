import math
from django.shortcuts import render
from django.shortcuts import render, redirect
from .models import Member
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import RegisterForm
from .forms import LoginForm
from django.contrib.auth import authenticate, login
import mysql.connector
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .forms import ProfileForm
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.core.paginator import Paginator
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.core.exceptions import ImproperlyConfigured
import json
from datetime import datetime
from django.contrib import messages
from .models import Hire, Member, HireforAdmin, Resource, PredictHire
import bcrypt
import re
from django.urls import reverse
from django.db.models import Count
import os 
import joblib
import numpy as np
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
import os
import io
from django.http import HttpResponse
import random
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils.timezone import now
from django.core.exceptions import ObjectDoesNotExist

# Create your views here.

def base(request):
    return render(request,"base.html")

def main(request):
    return render(request,"main.html")

def about(request):
    return render(request,"about.html")

def product(request):
    return render(request,"product.html")

def hire(request):
    if not request.user.is_authenticated:
        return redirect('login')  # ถ้าผู้ใช้ยังไม่ได้ล็อกอิน ให้เด้งไปหน้า Login
    return render(request, 'hire.html')

def profile_edit_view(request):
    if not request.user.is_authenticated:
        return redirect('login')  # ถ้าผู้ใช้ยังไม่ได้ล็อกอิน ให้เด้งไปหน้า Login
    return render(request, 'editprofile.html')

def contact(request):
    return render(request,"contact.html")

def product(requset):
    return render(requset,"product.html")

def show_login(request):
    return render(request, "login.html")

def register(requset):
    return render(requset, "register.html")

def editprofile(requset):
    return render(requset, "editprofile.html")

def dashboard(requset):
    return render(requset, "dashboard.html")

def hire(requset):
    return render(requset, "hire.html")

def hireset(requset):
    return render(requset, "hireset.html")

def adminhire(request):
    return render(request, 'adminhire.html')  # ชี้ไปที่ไฟล์เทมเพลต

def predictcustom(request):
    return render(request, "predictcustom.html")

def report(request):
    return render(request, "report.html")

def check_user_in_database(username, password):
    db_settings = settings.DATABASES['default']
    with mysql.connector.connect(
        host=db_settings['HOST'],
        user=db_settings['USER'],
        passwd=db_settings['PASSWORD'],
        database=db_settings['NAME']
    ) as db:
        with db.cursor() as cursor:
            query = "SELECT * FROM myapp_member WHERE Username=%s AND Password=%s"
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            return user is not None


def login(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        # ตรวจสอบว่ามีการกรอกข้อมูลในช่อง Username และ Password หรือไม่
        if not username:
            return render(request, 'login.html', {
                'error_message': 'Username is required.',
                'error_field': 'username',
            })

        if not password:
            return render(request, 'login.html', {
                'error_message': 'Password is required.',
                'error_field': 'password',
            })

        # ตรวจสอบความยาวของ Username และ Password
        if len(username) > 20:
            return render(request, 'login.html', {
                'error_message': 'Invalid Username or Password.',
                'error_field': 'username',
            })

        if len(password) > 100:
            return render(request, 'login.html', {
                'error_message': 'Invalid Username or Password.',
                'error_field': 'password',
            })

        # ตรวจสอบรูปแบบของ Username (ไม่ให้มีอักขระพิเศษ)
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return render(request, 'login.html', {
                'error_message': 'Invalid Username or Password.',
                'error_field': 'username',
            })

        # ตรวจสอบข้อมูลผู้ดูแลระบบ
        if username == 'admin' and password == 'admin':
            request.session['username'] = username
            return render(request, 'login.html', {
                'success_message': 'Login successful! Redirecting...',
                'redirect_url': 'dashboard',
            })

        # ตรวจสอบข้อมูลผู้ใช้ปกติในฐานข้อมูล
        try:
            user = Member.objects.get(Username=username)  # Django ORM ป้องกัน SQL Injection โดยอัตโนมัติ

            # ตรวจสอบรหัสผ่านด้วย Bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), user.Password.encode('utf-8')):
                request.session['customer_id'] = user.Customer_ID  # เก็บ Customer_ID ไว้ในเซสชัน
                request.session['username'] = user.Username  # เก็บ Username
                return render(request, 'login.html', {
                    'success_message': 'Login successful! Redirecting...',
                    'redirect_url': 'main',
                })
            else:
                # แสดงข้อความ Invalid username or password
                return render(request, 'login.html', {
                    'error_message': 'Invalid username or password.',
                    'error_field': 'password',
                })
        except Member.DoesNotExist:
            # แสดงข้อความ Invalid username or password
            return render(request, 'login.html', {
                'error_message': 'Invalid username or password.',
                'error_field': 'username',
            })
        except Exception as e:
            # จัดการข้อผิดพลาดอื่น ๆ และแสดงข้อความทั่วไป
            return render(request, 'login.html', {
                'error_message': 'Invalid Username or Password.',
                'error_field': 'general',
            })

    # กรณี GET (ไม่มีการแสดง error_message)
    return render(request, 'login.html')  # ไม่มี error_message


def register_user(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            try:
                # ✅ ตรวจสอบว่า Username ไม่มีอักขระพิเศษ
                username = form.cleaned_data.get('Username')
                if not username or not re.match(r'^[A-Za-z0-9]+$', username):
                    form.add_error('Username', 'The username must not contain special characters.')

                # ✅ ตรวจสอบว่ากรอกวันเกิดหรือไม่
                birth_date = form.cleaned_data.get('Birthday')
                if not birth_date:
                    form.add_error('Birthday', 'Please enter your date of birth.')

                # ✅ ตรวจสอบเบอร์โทรศัพท์ว่าถูกต้องหรือไม่
                phone_number = form.cleaned_data.get('Phone')
                if not phone_number or not re.match(r'^\d{10}$', phone_number):
                    form.add_error('Phone', 'Please enter a valid phone number.')

                # ✅ ตรวจสอบรหัสผ่านว่าปลอดภัยหรือไม่
                password = form.cleaned_data.get('Password')
                password_criteria = (
                    r'^(?=.*[A-Z])'        # ต้องมีตัวอักษรพิมพ์ใหญ่
                    r'(?=.*\d)'            # ต้องมีตัวเลข
                    r'(?=.*[@$!%*?&^#_])'  # ต้องมีอักขระพิเศษ
                    r'[A-Za-z\d@$!%*?&]{8,}$'  # อย่างน้อย 8 ตัวอักษร
                )
                if not password or not re.match(password_criteria, password):
                    form.add_error('Password', 'At least 8 characters long and must include an uppercase letter and a special character.')

                # ✅ ตรวจสอบว่า Email อยู่ในรูปแบบที่ถูกต้องหรือไม่
                email = form.cleaned_data.get('Email')
                if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                    form.add_error('Email', 'Please enter a valid format, such as including "@".')

                # ✅ รวมข้อมูลที่อยู่ก่อนบันทึกลง Address
                house_number = request.POST.get('house_number', '').strip()
                district = request.POST.get('district', '').strip()
                amphoe = request.POST.get('amphoe', '').strip()
                province = request.POST.get('province', '').strip()
                zipcode = request.POST.get('zipcode', '').strip()

                # ✅ ตรวจสอบว่าผู้ใช้กรอกข้อมูลที่อยู่ครบถ้วน
                if not (house_number and district and amphoe and province and zipcode):
                    form.add_error(None, 'Please fill in all address fields.')

                # ✅ รวมข้อมูลที่อยู่เป็นข้อความเดียว
                address = f"{house_number} ต.{district} อ.{amphoe} จ.{province} {zipcode}"

                # ✅ หากมีข้อผิดพลาดในฟอร์ม
                if form.errors:
                    return render(request, 'register.html', {'form': form})

                # ✅ ถ้าไม่มีข้อผิดพลาด ให้ดำเนินการบันทึกข้อมูล
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                # ✅ บันทึกฟอร์มพร้อมรหัสผ่านที่ถูก Hash และ Address ที่รวมแล้ว
                member = form.save(commit=False)
                member.Password = hashed_password.decode('utf-8')  # บันทึกรหัสผ่านแบบ Hash
                member.Address = address  # ✅ บันทึกข้อมูลที่อยู่ที่รวมแล้วลงใน `Address`
                member.save()

                # ✅ **แทรก success_message และ redirect_url ไปที่ `register.html`**
                return render(request, 'register.html', {
                    'form': RegisterForm(),
                    'success_message': 'Register successful!',
                    'redirect_url': 'login',
                })

            except Exception as e:
                print(f"Error saving user: {str(e)}")  # ✅ Debug ข้อผิดพลาดใน Terminal
                form.add_error(None, 'An error occurred while saving. Please try again.')

        else:
            print("Form validation failed:", form.errors)  # ✅ Debug form validation

    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})

def profile_edit_view(request):
    username = request.session.get('username')

    if not username:
        messages.warning(request, "กรุณาเข้าสู่ระบบก่อนแก้ไขโปรไฟล์")
        return redirect('login')  # ถ้าผู้ใช้ไม่ได้ล็อกอิน ให้ไปหน้า login

    try:
        member = Member.objects.get(Username=username)
    except ObjectDoesNotExist:
        messages.error(request, "ไม่พบข้อมูลสมาชิกของคุณ")
        return redirect('main')  # หรือจะเปลี่ยนเป็น redirect ไปหน้า login ก็ได้

    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=member)
        if form.is_valid():
            form.save()
            messages.success(request, "อัปเดตโปรไฟล์สำเร็จ")
            return redirect('main')  # หรือหน้าที่ต้องการให้กลับไป
        else:
            messages.error(request, "กรุณาตรวจสอบข้อมูลที่กรอก")
    else:
        form = ProfileForm(instance=member)

    return render(request, 'editprofile.html', {'form': form})

def edit_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.user)
        
        if form.is_valid():
            profile = form.save(commit=False)  # ยังไม่บันทึกลงฐานข้อมูล

            new_password = form.cleaned_data.get("Password")  # ดึงค่ารหัสผ่านจากฟอร์ม
            
            if new_password == "********":
                # ถ้าผู้ใช้ไม่ได้เปลี่ยนรหัสผ่าน ให้ใช้รหัสผ่านเดิม
                profile.Password = request.user.Password
            else:
                # ถ้าผู้ใช้เปลี่ยนรหัสผ่าน ค่อยแฮชรหัสใหม่ก่อนบันทึก
                profile.Password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            profile.save()  # บันทึกข้อมูลลงฐานข้อมูล

            return render(request, 'editprofile.html', {
                'toast_message': 'Profile updated successfully!',
                'toast_type': 'success',
                'redirect_url': reverse('main'),  # สร้าง URL สำหรับเปลี่ยนหน้า
            })
        else:
            return render(request, 'editprofile.html', {
                'toast_message': 'There was an error updating your profile.',
                'toast_type': 'error',
                'form': form,
            })
    else:
        form = ProfileForm(instance=request.user)

    return render(request, 'editprofile.html', {'form': form})

def dashboard(request):
    # ✅ ดึงข้อมูลสมาชิกทั้งหมด และเรียงตาม Customer_ID
    members_list = Member.objects.all().order_by('Customer_ID')

    # ✅ แบ่งข้อมูลเป็น 10 รายการต่อหน้า
    paginator = Paginator(members_list, 10)
    page_number = request.GET.get('page')
    members = paginator.get_page(page_number)

    # ✅ นับจำนวนสมาชิกทั้งหมด
    member_count = members_list.count()

    # ✅ นับจำนวนงานทั้งหมด (รวมทั้งของปกติและของ Admin)
    job_count = Hire.objects.count()
    jobA_count = HireforAdmin.objects.count()
    total_jobs = job_count + jobA_count

    # ✅ นับจำนวนงานที่อยู่ในสถานะ 'in_progress'
    in_progress_jobs = Hire.objects.filter(Status='in_progress').count()
    in_progressA_jobs = HireforAdmin.objects.filter(Status='in_progress').count()
    total_progress = in_progress_jobs + in_progressA_jobs

    # ✅ นับจำนวนงานที่มีสถานะ 'completed'
    completed_jobs = Hire.objects.filter(Status='completed').count()
    completedA_jobs = HireforAdmin.objects.filter(Status='completed').count()
    total_completed = completed_jobs + completedA_jobs

    # ✅ ส่งค่าที่ได้ไปยัง Template
    return render(request, 'dashboard.html', {
        'members': members,
        'member_count': member_count,
        'job_count': total_jobs,
        'in_progress_jobs': total_progress,
        'completed_jobs': total_completed
    })

def logout(request):
    print("Before flush:", request.session.items())
    request.session.flush()
    print("After flush:", request.session.items())
    return redirect('login')

def get_member(request, member_id):
    # ดึงข้อมูลสมาชิกจาก Customer_ID
    member = get_object_or_404(Member, Customer_ID=member_id)
    return JsonResponse({
        'id': member.Customer_ID,
        'username': member.Username,
        'firstname': member.Firstname,
        'lastname': member.Lastname,
        'password': member.Password,
        'email': member.Email,
        'phone': member.Phone,
        'address': member.Address,
        'birthday': member.Birthday.strftime('%Y-%m-%d') if member.Birthday else None,
    })


@csrf_exempt
## ของ admin
def update_member(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            customer_id = data.get('Customer_ID')
            if not customer_id:
                return JsonResponse({'status': 'error', 'message': 'Customer_ID is required'})

            member = Member.objects.get(Customer_ID=customer_id)

            # อัปเดตรหัสผ่าน (ใช้ bcrypt แฮชใน Backend)
            new_password = data.get('password')
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                member.Password = hashed_password.decode('utf-8')  # เก็บค่า hashed เป็น string

            # อัปเดตข้อมูลอื่น ๆ
            member.Firstname = data.get('firstname', member.Firstname)
            member.Lastname = data.get('lastname', member.Lastname)
            member.Email = data.get('email', member.Email)
            member.Phone = data.get('phone', member.Phone)
            member.Address = data.get('address', member.Address)
            member.Birthday = data.get('birthday', member.Birthday)
            member.save()

            return JsonResponse({'status': 'success', 'message': 'Member updated successfully'})

        except Member.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Member not found'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def submit_hire(request):
    if request.method == 'POST':
        try:
            customer_id = request.session.get('customer_id')
            if not customer_id:
                return render(request, 'hire.html', {'error_message': 'Customer ID not found in session!'})

            try:
                customer = Member.objects.get(Customer_ID=customer_id)
            except Member.DoesNotExist:
                return render(request, 'hire.html', {'error_message': 'Customer not found!'})

            width = request.POST.get('width')
            length = request.POST.get('length')
            height = request.POST.get('height')
            job_type = request.POST.get('job_type')
            budget = request.POST.get('budget')
            location = request.POST.get('location')  # ✅ แทรกการรับค่า Location ที่ผู้ใช้กรอกเข้ามา

            if not all([width, length, height, job_type, budget, location]):
                return render(request, 'hire.html', {'error_message': 'กรุณากรอกข้อมูลให้ครบถ้วน!'})

            # ✅ Debugging เพื่อตรวจสอบค่าที่ได้รับ
            print("DEBUG: Location =", location)

            hire = Hire.objects.create(
                Customer_ID=customer,
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Budget=budget,
                Location=location  # ✅ ใช้ค่าที่รับมาจากฟอร์ม
            )

            area = round(float(width) * float(length) * float(height), 2)

            def round_custom(value):
                return math.ceil(value) if value - math.floor(value) >= 0.5 else math.floor(value)

            wood = area / 2.5

            # เรียกใช้งานฟังก์ชัน predictionder
            response = predictionder(width, length, height, job_type, budget)
            
            if "error" in response:
                return render(request, 'hire.html', {'error_message': 'Prediction Error'})

            predict_hire = PredictHire.objects.create(
                HireC_ID=hire,
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Budget=budget,
                Area=area,
                Wood=round_custom(wood),
                Paint=response.get('Paint', 0),
                Chair=response.get('Chair', 0),
                Lighting=response.get('Lighting', 0),
                Nail=response.get('Nail', 0),
                Table=response.get('Table', 0)
            )

            return JsonResponse({
                'success': True,
                'message': 'บันทึกข้อมูลสำเร็จ',
                'PredictHire_ID': predict_hire.pk,
                'predict_hire': {
                    'Width': predict_hire.Width,
                    'Length': predict_hire.Length,
                    'Height': predict_hire.Height,
                    'Type': predict_hire.Type,
                    'Budget': predict_hire.Budget,
                    'Area': predict_hire.Area,
                    'Wood': predict_hire.Wood,
                    'Paint': predict_hire.Paint,
                    'Chair': predict_hire.Chair,
                    'Lighting': predict_hire.Lighting,
                    'Nail': predict_hire.Nail,
                    'Table': predict_hire.Table,
                }
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


'''def hire_list(request):
        # ดึงข้อมูลทั้งหมดจากตาราง Hire และเรียงลำดับตาม HireC_ID จากน้อยไปมาก
    predicts = PredictHire.objects.select_related('HireC_ID', 'HireC_ID__Customer_ID')\
                                 .filter(HireC_ID__isnull=False)\
                                 .order_by('HireC_ID')  # เรียงลำดับตาม HireC_ID จากน้อยไปมาก
    return render(request, 'hireset.html', {'predicts': predicts})  # เปลี่ยนชื่อไฟล์ Template เป็น hireset.html'''

from django.core.paginator import Paginator
from django.shortcuts import render
from .models import PredictHire

def hire_list(request):
    # ดึงค่าหมายเลขหน้าจาก request (ค่าเริ่มต้นเป็นหน้า 1)
    page_number = request.GET.get('page', 1)

    # ดึงข้อมูลจากฐานข้อมูล และเรียงลำดับตาม HireC_ID
    predicts = PredictHire.objects.select_related('HireC_ID', 'HireC_ID__Customer_ID')\
                                  .filter(HireC_ID__isnull=False)\
                                  .order_by('HireC_ID')

    # ใช้ Paginator แบ่งหน้า (12 รายการต่อหน้า)
    paginator = Paginator(predicts, 12)
    page_obj = paginator.get_page(page_number)

    return render(request, 'hireset.html', {'page_obj': page_obj})

@csrf_exempt
def delete_member(request, member_id):
    if request.method == 'DELETE':
        try:
            member = Member.objects.get(pk=member_id)  # ค้นหา member ด้วย ID
            member.delete()  # ลบข้อมูล
            return JsonResponse({"message": "Member deleted successfully."}, status=200)
        except Member.DoesNotExist:
            return JsonResponse({"error": "Member not found."}, status=404)
    return JsonResponse({"error": "Invalid request method."}, status=400)

def hash_password(password):
    # ใช้ bcrypt.gensalt() เพื่อสร้าง salt และ bcrypt.hashpw() เพื่อ hash รหัสผ่าน
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed

def check_password(plain_password, hashed_password):
    # ใช้ bcrypt.checkpw() เพื่อเปรียบเทียบรหัสผ่าน
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def check_duplicate(request):
    field = request.GET.get('field')  # ชื่อฟิลด์ที่ต้องการตรวจสอบ เช่น Username หรือ Email
    value = request.GET.get('value')  # ค่าที่ผู้ใช้กรอกมา

    # กำหนดฟิลด์ที่อนุญาตและวิธีการกรอง
    allowed_fields = {
        'Username': 'Username',
        'Email': 'Email',
    }

    # ตรวจสอบฟิลด์ที่ส่งมาว่าถูกต้องหรือไม่
    if field not in allowed_fields or not value:
        return JsonResponse({'error': 'Invalid field or value'}, status=400)

    # ตรวจสอบค่าซ้ำในฐานข้อมูล
    filter_criteria = {allowed_fields[field]: value}
    exists = Member.objects.filter(**filter_criteria).exists()

    # ส่งผลลัพธ์กลับไป
    if exists:
        return JsonResponse({'duplicate': True, 'message': f'{field} already exists'})
    return JsonResponse({'duplicate': False, 'message': f'{field} is available'})

@csrf_exempt  # ใช้ในกรณีที่ต้องการปิดการป้องกัน CSRF
def delete_hire(request, hire_id):
    if request.method == 'DELETE':
        try:
            hire = Hire.objects.get(pk=hire_id)  # ค้นหา Hire ด้วย Hire_ID
            hire.delete()  # ลบข้อมูลในฐานข้อมูล
            return JsonResponse({"message": f"Hire ID {hire_id} deleted successfully."}, status=200)
        except Hire.DoesNotExist:
            return JsonResponse({"error": f"Hire ID {hire_id} not found."}, status=404)
    return JsonResponse({"error": "Invalid request method. Use DELETE."}, status=400)

@csrf_exempt
def get_hire_details(request, hire_id):
    hire = get_object_or_404(Hire, pk=hire_id)
    data = {
        "Hire_ID": hire.Hire_ID,
        "Width": hire.Width,
        "Length": hire.Length,
        "Height": hire.Height,
        "Type": hire.Type,
        "Budget": hire.Budget,
        "Location": hire.Location,
        "Status": hire.Status
    }
    return JsonResponse(data)

@csrf_exempt
def update_hire_status(request, hire_id):
    if request.method == 'POST':
        try:
            hire = get_object_or_404(Hire, pk=hire_id)
            data = json.loads(request.body)
            hire.Status = data.get('Status')
            hire.save()
            return JsonResponse({"message": "Hire status updated successfully."}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=400)

def filter_hire_by_date(request):
    # ดึงข้อมูลจากฐานข้อมูล
    hires = Hire.objects.all()

    # ตรวจสอบค่าตัวกรองที่ส่งมาจากฟอร์ม
    sort_order = request.GET.get('sort_order', 'desc')  # ค่าเริ่มต้น: จากล่าสุดก่อน
    if sort_order == 'asc':
        hires = hires.order_by('Dateofhire')  # เรียงจากน้อยไปมาก (เก่าสุดก่อน)
    else:
        hires = hires.order_by('-Dateofhire')  # เรียงจากมากไปน้อย (ล่าสุดก่อน)

    # ส่งข้อมูลไปยัง Template
    return render(request, 'hireset.html', {'hires': hires})

# ฟังก์ชันดึงข้อมูลจากฐานข้อมูลและส่งกลับเป็น JSON
def report_chart(request):
    quarterly_data = {
        'Q1': {'in_progress': 0, 'completed': 0, 'Waiting_confirmation': 0},
        'Q2': {'in_progress': 0, 'completed': 0, 'Waiting_confirmation': 0},
        'Q3': {'in_progress': 0, 'completed': 0, 'Waiting_confirmation': 0},
        'Q4': {'in_progress': 0, 'completed': 0, 'Waiting_confirmation': 0}
    }

    hires = Hire.objects.all()
    for hire in hires:
        month = hire.Dateofhire.month
        if month in [1, 2, 3]:
            quarter = 'Q1'
        elif month in [4, 5, 6]:
            quarter = 'Q2'
        elif month in [7, 8, 9]:
            quarter = 'Q3'
        elif month in [10, 11, 12]:
            quarter = 'Q4'

        quarterly_data[quarter][hire.Status] += 1

    return JsonResponse(quarterly_data)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'Model')

try:
    model_chair = joblib.load(os.path.join(MODEL_DIR, 'model_chair.pkl'))
    model_lighting = joblib.load(os.path.join(MODEL_DIR, 'model_lighting.pkl'))
    model_table = joblib.load(os.path.join(MODEL_DIR, 'model_table.pkl'))
    model_paint_group1 = joblib.load(os.path.join(MODEL_DIR, 'paint', 'model_paint1.pkl'))
    model_paint_group2 = joblib.load(os.path.join(MODEL_DIR, 'paint', 'model_paint2.pkl'))
    model_nail_group1 = joblib.load(os.path.join(MODEL_DIR, 'nail', 'model_nail1.pkl'))
    model_nail_group2 = joblib.load(os.path.join(MODEL_DIR, 'nail', 'model_nail2.pkl'))
except Exception as e:
    raise ImproperlyConfigured(f"Error loading models: {e}")

def prediction(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8'))  # อ่าน JSON request
            
            width_input = float(data.get('width', 0))
            length_input = float(data.get('length', 0))
            height_input = float(data.get('height', 0))
            job_type = data.get('type')
            budget_input = data.get('budget')
            area = width_input * length_input * height_input
            wood = area / 3
            label_type = 1 if job_type == 'Booth' else 0

            def predicted_paint(area, width_input, height_input, length_input):
                input_data = np.array([[area, width_input, height_input, length_input]])
                if area / 15 <= model_paint_group1.predict(input_data):
                    return model_paint_group1.predict(input_data)[0]
                else:
                    return model_paint_group2.predict(input_data)[0]

            def predicted_nail(area, width_input, height_input):
                input_data = np.array([[area, width_input, height_input]])
                if area >= 60 and model_nail_group1.predict(input_data) < 18:
                    return model_nail_group1.predict(input_data)[0]
                else:
                    return model_nail_group2.predict(input_data)[0]
                
            def round_custom(value):
                return math.ceil(value) if value - math.floor(value) >= 0.5 else math.floor(value)
            
            input_data_forchair = pd.DataFrame({
                'Budget': [budget_input],
                'Width': [width_input],
                'Length': [length_input],
                'Height': [height_input],
                'Wood (sm.)': [area],
                'Booth': [label_type]
            })

            input_data_forlight = pd.DataFrame({
                'Budget': [budget_input],
                'Width': [width_input],
                'Length': [length_input],
                'Height': [height_input],
                'Wood (sm.)': [area]
            })

            input_data_fortable = pd.DataFrame({
                'Budget': [budget_input],
                'Width': [width_input],
                'Length': [length_input],
                'Height': [height_input],
                'Wood (sm.)': [area],
                'Wood (pc.)': [wood],
                'Booth': [label_type]
            })

            predict_paint = predicted_paint(area, width_input, height_input, length_input)
            predict_chair = model_chair.predict(input_data_forchair)[0]
            predict_lighting = model_lighting.predict(input_data_forlight)[0]
            predict_nail = predicted_nail(area, width_input, height_input)
            predict_table = model_table.predict(input_data_fortable)[0]

            Paint = round_custom(predict_paint)
            Chair = round_custom(predict_chair)
            Lighting =  round_custom(predict_lighting)
            Nail = round_custom(predict_nail)
            Table = round_custom(predict_table)

            return JsonResponse({
                "Paint": Paint,
                "Chair": Chair,
                "Lighting": Lighting,
                "Nail": Nail,
                "Table": Table
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)  # ส่ง Error Response
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

def submit_hireA(request):
    if request.method == 'POST':
        try:
            # ✅ อ่านค่าจาก request.body (JSON)
            data = json.loads(request.body)
            print("📌 Data received:", data)  # ตรวจสอบข้อมูลที่รับมา

            width = data.get('width')
            length = data.get('length')
            height = data.get('height')
            job_type = data.get('job_type')
            budget = data.get('budget')
            location = data.get('location')
            paint = data.get('paint')
            chair = data.get('chair')
            lighting = data.get('lighting')
            nail = data.get('nail')
            table = data.get('table')

            # ✅ ตรวจสอบว่าข้อมูลที่ได้รับมาครบหรือไม่
            if not all([width, length, height, job_type, budget, location]):
                print("❌ Missing required fields")
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # ✅ แสดงค่าที่รับมา
            print(f"📌 Width: {width}, Length: {length}, Height: {height}")
            print(f"📌 Job Type: {job_type}, Budget: {budget}, Location: {location}")
            print(f"📌 Paint: {paint}, Chair: {chair}, Lighting: {lighting}, Nail: {nail}, Table: {table}")

            # ✅ คำนวณพื้นที่
            area = round(float(width) * float(length) * float(height), 2)

            def round_custom(value):
                return math.ceil(value) if value - math.floor(value) >= 0.5 else math.floor(value)

            wood = area / 2.5
            # ✅ บันทึกข้อมูลลงในตาราง HireforAdmin
            hire_admin = HireforAdmin.objects.create(
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Budget=budget,
                Location=location
            )

            # ✅ บันทึกข้อมูลลงใน PredictHire
            predict_admin = PredictHire.objects.create(
                HireA_ID=hire_admin,
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Budget=budget,
                Area=area,
                Wood=round_custom(wood),
                Paint=paint,
                Chair=chair,
                Lighting=lighting,
                Nail=nail,
                Table=table
            )

            print("✅ Data saved successfully!")
            return JsonResponse({
                'success': True,
                'message': 'บันทึกข้อมูลสำเร็จ!',
                'hire_id': hire_admin.HireA_ID,
                'predict_id': predict_admin.Predict_ID
            })

        except Exception as e:
            print(f"❌ Error in submit_hireA: {str(e)}")  # ตรวจสอบ error ที่เกิดขึ้น
            return JsonResponse({'error': f'เกิดข้อผิดพลาด: {str(e)}'}, status=500)

    return render(request, 'dashboard.html')

def predictionder(width, length, height, job_type, budget):
    try:
        width_input = float(width)
        length_input = float(length)
        height_input = float(height)
        area = width_input * length_input * height_input
        wood = area / 3
        label_type = 1 if job_type == 'Booth' else 0

        def predicted_paint(area, width_input, height_input, length_input):
            input_data = np.array([[area, width_input, height_input, length_input]])
            if area / 15 <= model_paint_group1.predict(input_data):
                return model_paint_group1.predict(input_data)[0]
            else:
                return model_paint_group2.predict(input_data)[0]

        def predicted_nail(area, width_input, height_input):
            input_data = np.array([[area, width_input, height_input]])
            if area >= 60 and model_nail_group1.predict(input_data) < 18:
                return model_nail_group1.predict(input_data)[0]
            else:
                return model_nail_group2.predict(input_data)[0]

        def round_custom(value):
            return math.ceil(value) if value - math.floor(value) >= 0.5 else math.floor(value)
        
        input_data_forchair = pd.DataFrame({
            'Budget': [budget],
            'Width': [width_input],
            'Length': [length_input],
            'Height': [height_input],
            'Wood (sm.)': [area],
            'Booth': [label_type]
        })

        input_data_forlight = pd.DataFrame({
            'Budget': [budget],
            'Width': [width_input],
            'Length': [length_input],
            'Height': [height_input],
            'Wood (sm.)': [area]
        })

        input_data_fortable = pd.DataFrame({
            'Budget': [budget],
            'Width': [width_input],
            'Length': [length_input],
            'Height': [height_input],
            'Wood (sm.)': [area],
            'Wood (pc.)': [wood],
            'Booth': [label_type]
        })

        predict_paint = predicted_paint(area, width_input, height_input, length_input)
        predict_chair = model_chair.predict(input_data_forchair)[0]
        predict_lighting = model_lighting.predict(input_data_forlight)[0]
        predict_nail = predicted_nail(area, width_input, height_input)
        predict_table = model_table.predict(input_data_fortable)[0]

        Paint = round_custom(predict_paint)
        Chair = round_custom(predict_chair)
        Lighting = round_custom(predict_lighting)
        Nail = round_custom(predict_nail)
        Table = round_custom(predict_table)

        return {
            "Paint": Paint,
            "Chair": Chair,
            "Lighting": Lighting,
            "Nail": Nail,
            "Table": Table
        }
    except Exception as e:
        return {"error": str(e)}

#เหลือตั้งค่างบในแต่ละอั้น
def generate_pdf(request):
    print("✅ generate_pdf ถูกเรียกแล้ว")
    print("DEBUG: Session Data =", request.session.items())  # ดูค่าที่ถูกเก็บใน session
    customer_id = request.session.get('customer_id')
    print("DEBUG: Retrieved Customer_ID =", customer_id)
    predict_hire_id = request.GET.get("PredictHire_ID")

    print("DEBUG: Retrieved predict_ID =", predict_hire_id)

    #customer_id = request.GET.get("customer_id")
    # ✅ ถ้าไม่มี `Customer_ID` ให้แจ้งเตือน
    if not customer_id:
        return HttpResponse("ไม่พบ Customer_ID ในเซสชัน", status=400)
    if not predict_hire_id:
        return HttpResponse("ไม่พบ PredictHire_ID ใน request", status=400)

    # ✅ ใช้ `get_object_or_404()` เพื่อดึงข้อมูลสมาชิก
    member = get_object_or_404(Member, Customer_ID=customer_id)
    predict_hire = get_object_or_404(PredictHire, Predict_ID=predict_hire_id)
    hire = predict_hire.HireC_ID  # ✅ ดึง `Hire` ที่เกี่ยวข้อง

    firstname = member.Firstname
    lastname = member.Lastname
    address = member.Address
    job_type = predict_hire.Type
    amout_wood = predict_hire.Wood
    amout_paint = predict_hire.Paint
    amout_lighting = predict_hire.Lighting
    amout_nail = predict_hire.Nail
    amout_table = predict_hire.Table
    amout_chair = predict_hire.Chair
    location = hire.Location
    address = location if location else "ไม่ได้ระบุสถานที่"

    # ✅ ใช้ os.path.join() เพื่อให้พาธฟอนต์ถูกต้อง
    font_path = os.path.join(settings.BASE_DIR, "static", "fonts", "THSarabunNew.ttf")

    # ✅ ตรวจสอบว่าไฟล์ฟอนต์มีอยู่จริงก่อนใช้งาน
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("THSarabunNew", font_path))
        font_name = "THSarabunNew"
    else:
        font_name = "Helvetica"  # ใช้ฟอนต์ Default ถ้าไม่พบฟอนต์ไทย


    # ข้อมูลบริษัท
    company_name = "บริษัท เดอะวินเนอร์ อินทีเรีย & แอดเวอร์ไทซิ่ง จำกัด"
    company_address = "63/2476 ซ.ราษฎร์พัฒนา 5 ถนนราษฎร์พัฒนา เขตสะพานสูง กรุงเทพฯ 10240"
    company_tax = "เลขประจำตัวผู้เสียภาษี: 010 555 6022 673"
    company_contact = "โทรศัพท์: 081-440-5192 | Email: thewinnerceo.th@gmail.com"
    logo_path = os.path.join("static", "image", "Logo.jpg")

    # รายการสินค้า
    items = [
        ("Wood", amout_wood, "แผ่น"),
        ("Paint", amout_paint, "แกลลอน"),
        ("Lighting", amout_lighting, "ชุด"),
        ("Nail", amout_nail, "กล่อง"),
        ("Table", amout_table, "ตัว"),
        ("Chair", amout_chair, "ตัว")
    ]

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    # ✅ เพิ่มโลโก้บริษัท
    try:
        pdf.drawImage(logo_path, -100, 720, width=400, height=70)
    except:
        pass  # ถ้าไม่มีโลโก้ จะไม่แสดง (ป้องกัน error)

    # ✅ เพิ่มข้อมูลบริษัท (ใช้ฟอนต์ที่ถูกต้อง)
    pdf.setFont(font_name, 18)
    pdf.drawString(180, 780, company_name)

    pdf.setFont(font_name, 14)
    pdf.drawString(180, 760, company_address)
    pdf.drawString(180, 740, company_tax)
    pdf.drawString(180, 720, company_contact)

    # ✅ เพิ่มหัวข้อเอกสาร
    pdf.setFont(font_name, 18)
    pdf.drawString(200, 690, "ใบเสนอราคา / ใบสั่งซื้อ")
    
    # ✅ ขนาดของกรอบและตำแหน่งของตาราง
    table_width = 500  # ตั้งให้เท่ากันทั้งสองตาราง
    x_table_start = 45  # จุดเริ่มต้นของทั้งสองตาราง

    # ✅ กำหนดค่าตายตัวให้ y_start
    y_start = 610  

    pdf.setFont(font_name, 14)

    # ✅ วาดกรอบตารางข้อมูลลูกค้า (ด้านบน)
    pdf.rect(x_table_start, y_start - 30, table_width, 100, stroke=1, fill=0)  
    pdf.line(345, y_start + 70, 345, y_start - 30)  
    pdf.line(345, y_start + 35, x_table_start + table_width, y_start + 35)  

    # ✅ ลงทะเบียนฟอนต์ภาษาไทย
    font_path = "static/fonts/THSarabunNew.ttf"  # ✅ ปรับพาธให้ถูกต้อง
    pdfmetrics.registerFont(TTFont("THSarabunNew", font_path))

    # ✅ ใช้ styles สำหรับการตัดบรรทัดอัตโนมัติ
    styles = getSampleStyleSheet()
    style_address = styles["Normal"]
    style_address.fontName = "THSarabunNew"  # ✅ ใช้ฟอนต์ภาษาไทย
    style_address.fontSize = 14  # ✅ เพิ่มขนาดฟอนต์
    style_address.leading = 18   # ✅ ปรับระยะห่างระหว่างบรรทัดให้มากขึ้น

    # ✅ ปรับระยะห่างให้เหมาะสม
    x_label = 70   # ตำแหน่ง X สำหรับ Label (เช่น "ที่อยู่:")
    x_value = 130  # ตำแหน่ง X สำหรับค่าของลูกค้า
    y_gap = 15     # ลดระยะห่างระหว่างบรรทัด

    # ✅ ข้อมูลฝั่งซ้าย (ลูกค้า)
    pdf.drawString(x_label, y_start + 50, "ชื่อลูกค้า:")  
    pdf.drawString(x_value, y_start + 50, f"{firstname} {lastname}")  

    pdf.drawString(x_label, y_start + 50 - y_gap, "ชื่องาน:")      
    pdf.drawString(x_value, y_start + 50 - y_gap, job_type)  

    # ✅ ใช้ Paragraph เพื่อให้ "ที่อยู่" ตัดบรรทัดอัตโนมัติ และรองรับฟอนต์ไทย
    pdf.drawString(x_label, y_start + 50 - (y_gap * 2), "ที่อยู่:")

    # ✅ คำนวณความสูงของ Paragraph ล่วงหน้า
    address_paragraph = Paragraph(f"<font name='THSarabunNew' size=14>{address}</font>", style_address)  # ✅ ปรับขนาดฟอนต์ใน Paragraph
    w, h = address_paragraph.wrap(200, 60)  # ✅ เพิ่มความสูงให้รองรับฟอนต์ที่ใหญ่ขึ้น

    # ✅ ปรับตำแหน่งให้บรรทัดแรกของที่อยู่ อยู่ในระดับเดิม
    y_adjustment = h - 14  # ✅ ปรับให้ข้อความไม่ดันขึ้นไป

    address_paragraph.drawOn(pdf, x_value, y_start + 50 - (y_gap * 2) - y_adjustment)  # ✅ วางตำแหน่งให้บรรทัดแรกคงที่
    
    # ✅ ดึงวันที่ปัจจุบันและสุ่มเลข QC
    current_date = datetime.now().strftime("%d/%m/%Y")
    random_number = random.randint(10000, 99999)
    current_year = datetime.now().year
    qc_number = f"QC-{random_number}/{current_year}"

    # ✅ ข้อมูลฝั่งขวา (เลขที่และวันที่)
    pdf.drawString(360, y_start + 50, "เลขที่:")  
    pdf.drawString(400, y_start + 50, qc_number)  

    pdf.drawString(360, y_start + 15, "ว/ด/ป:")  
    pdf.drawString(400, y_start + 15, current_date)  

    # ✅ ปรับตำแหน่งให้ตารางสินค้าชิดกับตารางลูกค้า
    y_table_start = y_start - 50

    # ✅ คำนวณความสูงของตารางลูกค้า และกำหนดให้ตารางสินค้าเท่ากัน
    table_height = (len(items) + 3) * 20  # ความสูงของตารางสินค้า
    y_end = y_table_start - table_height  # คำนวณขอบล่างให้เท่ากัน

    # ✅ เพิ่มตารางรายการสินค้า
    data = [["ลำดับ", "รายละเอียด", "จำนวน", "หน่วย", "หมายเหตุ"]]
    for i, (desc, qty, unit) in enumerate(items, start=1):
        data.append([i, desc, qty, unit, "-"])


    # ❌ ลบ `pdf.rect()` ที่ใช้วาดกรอบรอบตารางสินค้า (เพื่อป้องกันเส้นซ้อน)
    # pdf.rect(x_table_start, y_end, table_width, table_height, stroke=1, fill=0)  # ลบออก

    # ✅ สร้างตารางสินค้า (ให้ Table ควบคุมเส้นเอง)
    table = Table(data, colWidths=[55, 200, 50, 100, 100])
    table.setStyle(TableStyle([
    ("FONTNAME", (0, 0), (-1, -1), "THSarabunNew"),  # ✅ ใช้ฟอนต์ไทย
    ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("GRID", (0, 0), (-1, -1), 1, colors.black),
]))

    table.wrapOn(pdf, x_table_start, 500)
    table.drawOn(pdf, x_table_start, y_end)  

    # ✅ ปรับตำแหน่งตารางเงื่อนไขการชำระเงินให้เลื่อนลงมา
    y_payment_start = y_start - 350  # ปรับระยะให้ตารางเงื่อนไขอยู่ต่ำลงจากตารางหลัก

    payment_data = [["งวดที่ชำระ", "รายละเอียด"]]
    payments = [
        ("งวดที่ 1", "50% เมื่อตกลงว่าจ้าง"),
        ("งวดที่ 2", "30% ก่อนเข้าพื้นที่ ดำเนินการงาน"),
        ("งวดที่ 3", "20% ก่อนรื้อถอน")
    ]
    for payment in payments:
        payment_data.append(payment)

    # ✅ ตรวจสอบว่าฟอนต์ภาษาไทยถูกต้อง
    pdfmetrics.registerFont(TTFont("THSarabunNew", "static/fonts/THSarabunNew.ttf"))

    # ✅ ปรับตารางเงื่อนไขการชำระเงินให้รองรับภาษาไทย
    payment_table = Table(payment_data, colWidths=[100, 350])
    payment_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "THSarabunNew"),  # ✅ ใช้ฟอนต์ภาษาไทย
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))

    payment_table.wrapOn(pdf, x_table_start, y_payment_start)
    payment_table.drawOn(pdf, x_table_start, y_payment_start)

    # ✅ เพิ่มพื้นที่สำหรับการลงนามที่มุมขวาล่าง
    signature_x = 350  # กำหนดตำแหน่ง X ของช่องลงชื่อ
    signature_y = 100  # กำหนดตำแหน่ง Y ของช่องลงชื่อ

    pdf.setFont("THSarabunNew", 14)
    pdf.drawString(signature_x, signature_y + 40, "ลงชื่อ................................................")  
    pdf.drawString(signature_x + 40, signature_y + 20, "(ชื่อ-นามสกุล)")  
    pdf.drawString(signature_x, signature_y, "วันที่.....................")  



    # ✅ บันทึก PDF
    pdf.save()
    buffer.seek(0)

    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="quotation.pdf"'
    return response

def get_predict_detailsC(request, predict_id):
    predict = get_object_or_404(PredictHire, pk=predict_id)
    data = {
        "Predict_ID": predict.Predict_ID,
        "Width": predict.Width,
        "Length": predict.Length,
        "Height": predict.Height,
        "Type": predict.Type,
        "Budget": predict.Budget,
        "Wood": predict.Wood,
        "Paint": predict.Paint,
        "Lighting": predict.Lighting,
        "Nail": predict.Nail,
        "Table": predict.Table,
        "Chair": predict.Chair,
        "DateOfHire": predict.HireC_ID.Dateofhire,
        "Type": predict.HireC_ID.Type,
        "Location": predict.HireC_ID.Location
    }
    return JsonResponse(data)

def submit_success_hire(request):
    if request.method == 'POST':
        try:
            # ✅ อ่าน JSON
            data = json.loads(request.body)
            print("📌 Data received from frontend:", json.dumps(data, indent=2))

            # ✅ ดึงค่าจาก JSON
            predict_id = data.get('Predict_ID')
            width = data.get('Width')
            length = data.get('Length')
            height = data.get('Height')
            job_type = data.get('Job_type')
            location = data.get('Location')
            budget = data.get('Budget')
            wood_p = data.get('Wood_P')  # ✅ แก้ให้ตรงกับ frontend
            paint_p = data.get('Paint_P')
            chair_p = data.get('Chair_P')
            lighting_p = data.get('Lighting_P')
            nail_p = data.get('Nail_P')
            table_p = data.get('Table_P')
            wood = data.get('Wood')
            paint = data.get('Paint')
            chair = data.get('Chair')
            lighting = data.get('Lighting')
            nail = data.get('Nail')
            table = data.get('Table')
            dateofhire = data.get('DateOfHire') or None  # ✅ ถ้าไม่มี ใช้ None

            # ✅ ตรวจสอบค่าที่จำเป็น
            required_fields = [predict_id, width, length, height, job_type, budget]
            if any(field is None for field in required_fields):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # ✅ ตรวจสอบว่า PredictHire มีอยู่จริง
            try:
                predict_instance = PredictHire.objects.get(Predict_ID=predict_id)
            except PredictHire.DoesNotExist:
                return JsonResponse({'error': 'PredictHire not found'}, status=404)

            # ✅ บันทึกลง DB
            resource_admin = Resource.objects.create(
                Predict_ID=predict_instance,
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Location=location,
                Budget=budget,
                Wood_P=wood_p,
                Paint_P=paint_p,
                Chair_P=chair_p,
                Lighting_P=lighting_p,
                Nail_P=nail_p,
                Table_P=table_p,
                Wood=wood,
                Paint=paint,
                Chair=chair,
                Lighting=lighting,
                Nail=nail,
                Table=table,
                Dateofhire=dateofhire
            )

            print("✅ Data saved successfully!")
            return JsonResponse({
                'success': True,
                'message': 'บันทึกข้อมูลสำเร็จ!',
                'predict_id': resource_admin.Predict_ID.Predict_ID,
                'resource_id': resource_admin.Resource_ID
            })

        except Exception as e:
            print(f"❌ Error in submit_success_hire: {str(e)}")
            return JsonResponse({'error': f'เกิดข้อผิดพลาด: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def delete_hireA(request, hire_id):
    if request.method == 'DELETE':
        try:
            HireforAdmins = HireforAdmin.objects.get(pk=hire_id)  # ค้นหา Hire ด้วย Hire_ID
            HireforAdmins.delete()  # ลบข้อมูลในฐานข้อมูล
            return JsonResponse({"message": f"HireA ID {hire_id} deleted successfully."}, status=200)
        except HireforAdmins.DoesNotExist:
            return JsonResponse({"error": f"HireA ID {hire_id} not found."}, status=404)
    return JsonResponse({"error": "Invalid request method. Use DELETE."}, status=400)

def get_hireA_details(request, hire_id):
    HireforAdmins = get_object_or_404(HireforAdmin, pk=hire_id)
    data = {
        "Hire_ID": HireforAdmins.HireA_ID,
        "Width": HireforAdmins.Width,
        "Length": HireforAdmins.Length,
        "Height": HireforAdmins.Height,
        "Type": HireforAdmins.Type,
        "Budget": HireforAdmins.Budget,
        "Location": HireforAdmins.Location,
        "Status": HireforAdmins.Status,
        "DateOfHire": HireforAdmins.Dateofhire
    }
    return JsonResponse(data)

def get_predict_detailsA(request, predict_id):
    predict = get_object_or_404(PredictHire, pk=predict_id)
    data = {
        "Predict_ID": predict.Predict_ID,
        "Width": predict.Width,
        "Length": predict.Length,
        "Height": predict.Height,
        "Type": predict.Type,
        "Budget": predict.Budget,
        "Wood": predict.Wood,
        "Paint": predict.Paint,
        "Lighting": predict.Lighting,
        "Nail": predict.Nail,
        "Table": predict.Table,
        "Chair": predict.Chair,
        "DateOfHire": predict.HireA_ID.Dateofhire,
        "Type": predict.HireA_ID.Type,
        "Location": predict.HireA_ID.Location
    }
    return JsonResponse(data)

def update_hireA_status(request, hire_id):
    if request.method == 'POST':
        try:
            HireforAdmins = get_object_or_404(HireforAdmin, pk=hire_id)
            data = json.loads(request.body)
            HireforAdmins.Status = data.get('Status')
            HireforAdmins.save()
            return JsonResponse({"message": "Hire status updated successfully."}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=400)

def filter_hireA_by_date(request):
    # ดึงข้อมูลจากฐานข้อมูล
    hires = HireforAdmin.objects.all()

    # ตรวจสอบค่าตัวกรองที่ส่งมาจากฟอร์ม
    sort_order = request.GET.get('sort_order', 'desc')  # ค่าเริ่มต้น: จากล่าสุดก่อน
    if sort_order == 'asc':
        hires = hires.order_by('Dateofhire')  # เรียงจากน้อยไปมาก (เก่าสุดก่อน)
    else:
        hires = hires.order_by('-Dateofhire')  # เรียงจากมากไปน้อย (ล่าสุดก่อน)

    # ส่งข้อมูลไปยัง Template
    return render(request, 'adminhire.html', {'hires': hires})

def hireA_list(request):
    # ดึงค่าหน้าปัจจุบันจาก request (ค่าเริ่มต้นคือ 1)
    page_number = request.GET.get('page', 1)

    # ดึงข้อมูลจากฐานข้อมูล
    predicts = PredictHire.objects.select_related('HireA_ID').filter(HireA_ID__isnull=False)

    # ใช้ Paginator เพื่อแบ่งข้อมูลเป็น 12 รายการต่อหน้า
    paginator = Paginator(predicts, 12)
    page_obj = paginator.get_page(page_number)

    return render(request, 'adminhire.html', {'page_obj': page_obj})

def Report_list(request):
    resources = Resource.objects.select_related(
        'Predict_ID',
        'Predict_ID__HireC_ID',
        'Predict_ID__HireC_ID__Customer_ID',
        'Predict_ID__HireA_ID'
    ).all()
    print(resources)
    return render(request, 'report.html', {'resources': resources})

def filter_hire_by_date(request):
    year = request.GET.get('year', '2024')  # ค่าปีเริ่มต้นเป็น 2024
    quarter = request.GET.get('quarter', '1')  # ค่าตั้งต้นเป็นไตรมาสที่ 1

    # กำหนดช่วงวันที่ตามไตรมาส
    quarter_dates = {
        "1": ("01-01", "03-31"),
        "2": ("04-01", "06-30"),
        "3": ("07-01", "09-30"),
        "4": ("10-01", "12-31"),
    }

    start_date = f"{year}-{quarter_dates[quarter][0]}"
    end_date = f"{year}-{quarter_dates[quarter][1]}"

    # แปลงเป็น datetime
    start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
    end_datetime = datetime.strptime(end_date, "%Y-%m-%d")

    # คัดกรองข้อมูลตามวันที่
    resources = Resource.objects.filter(Predict_ID__Dateofhire__range=(start_datetime, end_datetime))

    return render(request, 'report.html', {'resources': resources})

def get_resource_data(request):
    hire_id = request.GET.get("hire_id")

    resource = None
    try:
        resource = Resource.objects.get(Predict_ID__HireC_ID__Hire_ID=hire_id)
    except Resource.DoesNotExist:
        try:
            resource = Resource.objects.get(Predict_ID__HireA_ID__HireA_ID=hire_id)
        except Resource.DoesNotExist:
            return JsonResponse({"error": "Resource not found"}, status=404)

    data = {
        "Wood_P": resource.Wood_P,
        "Paint_P": resource.Paint_P,
        "Lighting_P": resource.Lighting_P,
        "Nail_P": resource.Nail_P,
        "Table_P": resource.Table_P,
        "Chair_P": resource.Chair_P,
        "Wood": resource.Wood,
        "Paint": resource.Paint,
        "Lighting": resource.Lighting,
        "Nail": resource.Nail,
        "Table": resource.Table,
        "Chair": resource.Chair,
    }
    return JsonResponse(data)

def get_resource_by_predict(request, predict_id):
    """
    ✅ ดึงข้อมูล Resource ตาม Predict_ID โดยไม่ใช้ Serializer
    """
    resource = get_object_or_404(Resource, Predict_ID__Predict_ID=predict_id)

    data = {
        "Resource_ID": resource.Resource_ID,
        "Predict_ID": resource.Predict_ID.Predict_ID,
        "Width": resource.Width,
        "Length": resource.Length,
        "Height": resource.Height,
        "Type": resource.Type,
        "Location": resource.Location,
        "Budget": resource.Budget,
        "Wood_P": resource.Wood_P,
        "Paint_P": resource.Paint_P,
        "Lighting_P": resource.Lighting_P,
        "Nail_P": resource.Nail_P,
        "Table_P": resource.Table_P,
        "Chair_P": resource.Chair_P,
        "Wood": resource.Wood,
        "Paint": resource.Paint,
        "Lighting": resource.Lighting,
        "Nail": resource.Nail,
        "Table": resource.Table,
        "Chair": resource.Chair,
        "Dateofhire": resource.Dateofhire,
        "DateSuccess": resource.DateSuccess,
    }

    return JsonResponse(data)