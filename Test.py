'''from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import PredictHire, HireforAdmin

@csrf_exempt
def SavePredictHire(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode('utf-8'))  # อ่าน JSON request

            # ✅ รับค่าจาก JSON
            width = float(data.get('width', 0))
            length = float(data.get('length', 0))
            height = float(data.get('height', 0))
            job_type = data.get('type')
            budget = float(data.get('budget', 0))
            paint = int(data.get('paint', 0))
            chair = int(data.get('chair', 0))
            lighting = int(data.get('lighting', 0))
            nail = int(data.get('nail', 0))
            table = int(data.get('table', 0))
            hire_id = data.get('hire_id')

            # ✅ ตรวจสอบว่า `HireA_ID` มีอยู่จริง
            try:
                hire_admin = HireforAdmin.objects.get(id=hire_id)
            except HireforAdmin.DoesNotExist:
                return JsonResponse({"error": "HireA_ID not found"}, status=400)

            # ✅ ตรวจสอบว่ามี `PredictHire` ที่เกี่ยวข้องหรือไม่
            predict_hire = PredictHire.objects.filter(HireA_ID=hire_admin).first()

            if predict_hire:
                # ✅ ถ้ามีข้อมูลอยู่แล้ว → ดึงข้อมูลเดิมกลับไป (ไม่สร้างใหม่)
                return JsonResponse({  
                    "success": "Prediction data found!",
                    "Predict_ID": predict_hire.Predict_ID,
                    "Width": predict_hire.Width,
                    "Length": predict_hire.Length,
                    "Height": predict_hire.Height,
                    "Type": predict_hire.Type,
                    "Budget": predict_hire.Budget,
                    "Area": predict_hire.Area,
                    "Wood": predict_hire.Wood,
                    "Paint": predict_hire.Paint,
                    "Chair": predict_hire.Chair,
                    "Lighting": predict_hire.Lighting,
                    "Nail": predict_hire.Nail,
                    "Table": predict_hire.Table,
                    "status": "Data Retrieved"
                })

            # ✅ ถ้ายังไม่มี `PredictHire` ให้สร้างใหม่
            predict_hire = PredictHire.objects.create(
                HireA_ID=hire_admin,  # ใช้ HireA_ID ที่มีอยู่
                Width=width,
                Length=length,
                Height=height,
                Type=job_type,
                Budget=budget,
                Area=round(width * length * height, 2),
                Wood=round((width * length * height) / 2.5),
                Paint=paint,
                Chair=chair,
                Lighting=lighting,
                Nail=nail,
                Table=table
            )

            return JsonResponse({
                "success": "Prediction data created successfully!",
                "Predict_ID": predict_hire.Predict_ID,
                "Width": predict_hire.Width,
                "Length": predict_hire.Length,
                "Height": predict_hire.Height,
                "Type": predict_hire.Type,
                "Budget": predict_hire.Budget,
                "Area": predict_hire.Area,
                "Wood": predict_hire.Wood,
                "Paint": predict_hire.Paint,
                "Chair": predict_hire.Chair,
                "Lighting": predict_hire.Lighting,
                "Nail": predict_hire.Nail,
                "Table": predict_hire.Table,
                "status": "Created"
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
'''