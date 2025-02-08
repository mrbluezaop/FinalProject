from django.contrib import admin
from django.apps import AppConfig

class MyAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'  # ต้องตรงกับชื่อโฟลเดอร์แอป

# Register your models here.
