from django.shortcuts import render, redirect
from .forms import RegisterForm
from django.http import HttpResponse
from myapp.models import Member
from django.contrib import messages
from django.contrib.auth.decorators import login_required


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # ส่งผู้ใช้ไปยังหน้า login
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

@login_required
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # ค้นหาข้อมูลผู้ใช้ในฐานข้อมูล MySQL
        try:
            user = Member.objects.get(Username=username, Psw=password)
            # หากพบข้อมูลผู้ใช้
            return redirect('main')  # และทำการ redirect ไปยังหน้าหลักหรือหน้าที่ต้องการ
        except Member.DoesNotExist:
            # หากไม่พบข้อมูลผู้ใช้
            messages.error(request, "Invalid username or password")  # เพิ่มข้อความแจ้งเตือน
            return render(request, 'login.html', {'error_message': 'Invalid username or password'})
    else:
        # แสดงหน้า Login สำหรับการส่งคำขอ GET
        return render(request, 'login.html')