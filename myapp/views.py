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
    return render(request,"hire.html")

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
            # ตรวจสอบว่า Username ไม่มีอักขระพิเศษ
            username = form.cleaned_data.get('Username')
            if not username or not re.match(r'^[A-Za-z0-9]+$', username):  # อนุญาตเฉพาะ A-Z, a-z, 0-9
                form.add_error('Username', 'Username ห้ามมีอักขระพิเศษ.')

            # ตรวจสอบว่ากรอกวันเกิดหรือไม่
            birth_date = form.cleaned_data.get('Birthday')
            if not birth_date:
                form.add_error('Birthday', 'กรุณากรอกวันเกิด.')

            # ตรวจสอบเบอร์โทรศัพท์ว่าถูกต้องหรือไม่
            phone_number = form.cleaned_data.get('Phone')
            if not phone_number or not re.match(r'^\d{10}$', phone_number):
                form.add_error('Phone', 'กรุณาเบอร์โทรศัพท์ให้ถูกต้อง.')

            # ตรวจสอบรหัสผ่านว่าปลอดภัยหรือไม่
            password = form.cleaned_data.get('Password')
            password_criteria = (
                r'^(?=.*[A-Z])'        # ต้องมีตัวอักษรพิมพ์ใหญ่
                r'(?=.*\d)'            # ต้องมีตัวเลข
                r'(?=.*[@$!%*?&^#_])'  # ต้องมีอักขระพิเศษ
                r'[A-Za-z\d@$!%*?&]{8,}$'  # อย่างน้อย 8 ตัวอักษร
            )
            if not password or not re.match(password_criteria, password):
                form.add_error('Password', 'อย่างน้อย 8 ตัว และต้องมีอักษรพิมพ์ใหญ่,และอักขระพิเศษ')

            # ตรวจสอบว่า Email อยู่ในรูปแบบที่ถูกต้องหรือไม่
            email = form.cleaned_data.get('Email')
            if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                form.add_error('Email', 'ผิด format.')

            # หากมีข้อผิดพลาดในฟอร์ม
            if form.errors:
                return render(request, 'register.html', {'form': form})

            # ถ้าไม่มีข้อผิดพลาด ให้ดำเนินการบันทึกข้อมูล
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # บันทึกฟอร์มพร้อมรหัสผ่านที่ถูก Hash
            member = form.save(commit=False)
            member.Password = hashed_password.decode('utf-8')
            member.save()

             # ส่งข้อความสำเร็จไปยังเทมเพลต
            return render(request, 'register.html', {
                'form': RegisterForm(),  # ส่งฟอร์มใหม่ (ว่างเปล่า)
                'success_message': 'Register successful!',  # ข้อความสำเร็จ
                'redirect_url': 'login',  # URL ที่จะเปลี่ยนเส้นทาง (ใช้ `url name` ของหน้า main)
            })
        else:
            # ส่งฟอร์มพร้อมข้อผิดพลาดกลับไป
            return render(request, 'register.html', {'form': form})
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


def profile_edit_view(request):
    username = request.session.get('username')
    member = Member.objects.get(Username=username)
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=member)
        if form.is_valid():
            form.save()
            return redirect('main')  # หรือหน้าที่คุณต้องการให้เป็นหน้าหลังจากบันทึก
    else:
        form = ProfileForm(instance=member)
    return render(request, 'editprofile.html', {'form': form})

def edit_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
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
    # ดึงข้อมูลสมาชิกทั้งหมด
    members_list = Member.objects.all()
    paginator = Paginator(members_list, 5)  # แบ่งข้อมูลสมาชิก 5 รายการต่อหน้า

    # ดึงหมายเลขหน้าจาก URL
    page_number = request.GET.get('page')
    members = paginator.get_page(page_number)

    # นับจำนวนสมาชิกทั้งหมด
    member_count = members_list.count()

    # นับจำนวนงานในฐานข้อมูล
    job_count = Hire.objects.count()

    # นับจำนวนงานที่มีสถานะเป็น 'in_progress'
    in_progress_jobs = Hire.objects.filter(Status='in_progress').count()

    # นับจำนวนงานที่มีสถานะเป็น 'completed'
    completed_jobs = Hire.objects.filter(Status='completed').count()

    context = {
        'in_progress_jobs': in_progress_jobs,
        'completed_jobs': completed_jobs,
    }

    # ส่งข้อมูลทั้งหมดไปยัง Template
    return render(request, 'dashboard.html', {
        'members': members,
        'member_count': member_count,
        'job_count': job_count,
        'in_progress_jobs' : in_progress_jobs,
        'completed_jobs': completed_jobs,
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
        # กำหนด Customer_ID จากเซสชัน (หรือวิธีอื่น)
        customer_id = request.session.get('customer_id')  # ต้องเก็บ customer_id ไว้ในเซสชัน
        if not customer_id:
            return render(request, 'hire.html', {'error_message': 'Customer ID not found in session!'})

        # ตรวจสอบว่า Customer_ID มีอยู่ในตาราง Member
        try:
            customer = Member.objects.get(Customer_ID=customer_id)
        except Member.DoesNotExist:
            return render(request, 'hire.html', {'error_message': 'Customer not found!'})

        # รับค่าจากฟอร์ม
        width = request.POST.get('width')
        length = request.POST.get('length')
        height = request.POST.get('height')
        job_type = request.POST.get('job_type')
        budget = request.POST.get('budget')
        location = request.POST.get('location')

        # บันทึกข้อมูลลงในโมเดล Hire
        hire = Hire(
            Customer_ID=customer,
            Width=width,
            Length=length,
            Height=height,
            Type=job_type,
            Budget=budget,
            Location=location
        )
        hire.save()

        # ส่งกลับหน้าเดิมพร้อมข้อความสำเร็จ
        return render(request, 'hire.html', {'success_message': 'คำสั่งซื้อของคุณถูกบันทึกเรียบร้อยแล้ว!'})

    # หากเป็น GET request ให้แสดงฟอร์ม
    return render(request, 'hire.html')

def hire_list(request):
    # ดึงข้อมูลทั้งหมดจากตาราง Hire
    hires = Hire.objects.select_related('Customer_ID').all()  # ใช้ select_related เพื่อรวมข้อมูลจาก ForeignKey
    return render(request, 'hireset.html', {'hires': hires})  # เปลี่ยนชื่อไฟล์ Template เป็น hireset.html

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