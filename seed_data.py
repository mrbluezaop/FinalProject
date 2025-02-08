import os
import django
from datetime import date
from myapp import Member  # เปลี่ยน 'your_app' เป็นชื่อแอปของคุณ

# ตั้งค่าตัวแปรสำหรับ Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')  # เปลี่ยน 'myproject' เป็นชื่อโปรเจกต์ของคุณ
django.setup()

def seed_members():
    """เพิ่มข้อมูลตัวอย่างลงในฐานข้อมูล Member"""
    members_data = [
        {"Username": "nattapon01", "Firstname": "ณัฐพล", "Lastname": "ทองดี", "Password": "password123", "Email": "nattapon01@example.com", "Phone": "0812345678", "Address": "123 ถนนพระราม 9 กรุงเทพ", "Birthday": date(1995, 3, 15)},
        {"Username": "sirikorn02", "Firstname": "ศิริกร", "Lastname": "วงศ์สุวรรณ", "Password": "securepass", "Email": "sirikorn02@example.com", "Phone": "0823456789", "Address": "456 ถนนลาดพร้าว กรุงเทพ", "Birthday": date(1992, 5, 20)},
        {"Username": "piyathida03", "Firstname": "ปิยะธิดา", "Lastname": "เกียรติศักดิ์", "Password": "mypassword", "Email": "piyathida03@example.com", "Phone": "0834567890", "Address": "789 ถนนรามอินทรา กรุงเทพ", "Birthday": date(1998, 8, 25)},
        {"Username": "kittipong04", "Firstname": "กิตติพงษ์", "Lastname": "แซ่ลี้", "Password": "pass12345", "Email": "kittipong04@example.com", "Phone": "0845678901", "Address": "111 ซอยสุขุมวิท 50 กรุงเทพ", "Birthday": date(1990, 11, 10)},
        {"Username": "supattra05", "Firstname": "สุภัทรา", "Lastname": "ธรรมรงค์", "Password": "supa2023", "Email": "supattra05@example.com", "Phone": "0856789012", "Address": "222 ซอยเอกมัย กรุงเทพ", "Birthday": date(1987, 2, 14)},
        {"Username": "tanakorn06", "Firstname": "ธนากร", "Lastname": "บุญมี", "Password": "tnkpass", "Email": "tanakorn06@example.com", "Phone": "0867890123", "Address": "333 ถนนบางนา-ตราด สมุทรปราการ", "Birthday": date(1993, 9, 30)},
        {"Username": "chananya07", "Firstname": "ชนัญญา", "Lastname": "จันทร์เพ็ญ", "Password": "chnpass", "Email": "chananya07@example.com", "Phone": "0878901234", "Address": "444 หมู่บ้านลุมพินี นนทบุรี", "Birthday": date(1996, 6, 5)},
        {"Username": "vorachai08", "Firstname": "วรชัย", "Lastname": "เจริญสุข", "Password": "vora123", "Email": "vorachai08@example.com", "Phone": "0889012345", "Address": "555 คอนโดเดอะไลน์ เชียงใหม่", "Birthday": date(1985, 12, 1)},
        {"Username": "suchada09", "Firstname": "สุชาดา", "Lastname": "ประเสริฐ", "Password": "sucpass", "Email": "suchada09@example.com", "Phone": "0890123456", "Address": "666 หมู่บ้านพฤกษา ปทุมธานี", "Birthday": date(2000, 4, 22)},
        {"Username": "arthit10", "Firstname": "อาทิตย์", "Lastname": "รัตนไพบูลย์", "Password": "artpass", "Email": "arthit10@example.com", "Phone": "0801234567", "Address": "777 ถนนเจริญกรุง กรุงเทพ", "Birthday": date(1991, 7, 7)},
    ]

    for data in members_data:
        Member.objects.get_or_create(**data)

    print("✅ เพิ่มข้อมูลตัวอย่างลงในตาราง Member สำเร็จ!")

if __name__ == "__main__":
    seed_members()
