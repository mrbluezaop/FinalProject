# ใช้ Python Base Image
FROM python:3.12

# ติดตั้ง MySQL Client
RUN apt-get update && apt-get install -y default-mysql-client

# ตั้งค่า environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# กำหนด working directory ภายใน container
WORKDIR /app

# คัดลอกไฟล์ requirements.txt และติดตั้ง dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# คัดลอกโค้ดโปรเจคทั้งหมดเข้า container
COPY . .

# คัดลอก seed_data.py เข้า container
# COPY seed_data.py ./

# ให้ entrypoint.sh มีสิทธิ์รันได้
RUN chmod +x /app/entrypoint.sh

# เปิดพอร์ต 8000 (พอร์ตของ Gunicorn)
EXPOSE 8000

# คำสั่งเริ่มต้น ใช้ entrypoint.sh
ENTRYPOINT ["sh", "/app/entrypoint.sh"]
