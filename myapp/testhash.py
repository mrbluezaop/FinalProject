import bcrypt
import pymysql

# เชื่อมต่อฐานข้อมูล
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='1234',
    database='dbthewinner',  # ชื่อฐานข้อมูล
    charset='utf8mb4'
)

try:
    # รับข้อมูลรหัสผ่านจากฐานข้อมูล
    with connection.cursor() as cursor:
        username = "nkr"  # ชื่อผู้ใช้ที่ต้องการตรวจสอบ
        # ใช้ชื่อเต็มของตาราง myapp_member
        cursor.execute("SELECT Password FROM myapp_member WHERE Username = %s", (username,))
        result = cursor.fetchone()
        
        if result is None:
            print("User not found!")
        else:
            stored_hash = result[0]  # Hash ที่เก็บในฐานข้อมูล
            
            # รหัสผ่านที่ผู้ใช้กรอก
            plain_password = "3213"
            
            # ตรวจสอบความตรงกัน
            if bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash.encode('utf-8')):
                print("Password matches!")
            else:
                print("Password does not match!")
finally:
    # ปิดการเชื่อมต่อ
    connection.close()
