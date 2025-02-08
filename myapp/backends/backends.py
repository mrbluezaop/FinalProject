from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.db import connection

class MySQLAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM my_user_table WHERE username=%s AND password=%s", [username, password])
            user_data = cursor.fetchone()
            if user_data:
                user = User(username=user_data[0], password=user_data[1])  # สร้าง User object จากข้อมูลที่ดึงมาจาก MySQL
                return user
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
