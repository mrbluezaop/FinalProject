'''from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.http import JsonResponse
from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd
import os

# โหลดโมเดล
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')

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

# สร้างฟังก์ชันช่วยสำหรับพยากรณ์

def predicted_paint(area_input, width_input, height_input, length_input):
    input_data = np.array([[area_input, width_input, height_input, length_input]])
    if area_input / 15 <= model_paint_group1.predict(input_data):
        return model_paint_group1.predict(input_data)[0]
    else:
        return model_paint_group2.predict(input_data)[0]

def predicted_nail(area_input, width_input, height_input):
    input_data = np.array([[area_input, width_input, height_input]])
    if area_input >= 60 and model_nail_group1.predict(input_data) < 18:
        return model_nail_group1.predict(input_data)[0]
    else:
        return model_nail_group2.predict(input_data)[0]

# สร้าง API Endpoint
class PredictionAPIView(APIView):
    def post(self, request):
        try:
            data = request.data
            width = float(data.get('width', 0))
            height = float(data.get('height', 0))
            length = float(data.get('length', 0))
            budget = float(data.get('budget', 0))
            booth = int(data.get('booth', 0))

            area_input = width * length * height
            wood = area_input / 2.5

            input_data = pd.DataFrame({
                'Budget': [budget],
                'Width': [width],
                'Length': [length],
                'Height': [height],
                'Wood (sm.)': [area_input],
                'Booth': [booth]
            })

            input_data_forlight = pd.DataFrame({
                'Budget': [budget],
                'Width': [width],
                'Length': [length],
                'Height': [height],
                'Wood (sm.)': [area_input]
            })

            input_data_fortable = pd.DataFrame({
                'Budget': [budget],
                'Width': [width],
                'Length': [length],
                'Height': [height],
                'Wood (sm.)': [area_input],
                'Wood (pc.)': [wood],
                'Booth': [booth]
            })

            predict_paint = predicted_paint(area_input, width, height, length)
            predict_chair = model_chair.predict(input_data)[0]
            predict_lighting = model_lighting.predict(input_data_forlight)[0]
            predict_nail = predicted_nail(area_input, width, height)
            predict_table = model_table.predict(input_data_fortable)[0]

            return Response({
                "Paint": round(predict_paint, 2),
                "Chair": round(predict_chair, 2),
                "Lighting": round(predict_lighting, 2),
                "Nail": round(predict_nail, 2),
                "Table": round(predict_table, 2)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# กำหนด URL Routing
from django.urls import path

urlpatterns = [
    path('predict/', PredictionAPIView.as_view(), name='predict'),
]
'''