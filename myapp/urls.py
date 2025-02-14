from django.urls import path
from myapp import views
from .views import filter_hire_by_date, filter_hireA_by_date
from django.conf import settings
from django.conf.urls.static import static
from .views import generate_pdf
from .views import get_resource_data


urlpatterns = [
    path('base/', views.base, name='base'),
    path('main/', views.main, name='main'),
    path('about/', views.about, name='about'),
    path('product/', views.product, name='product'),
    path('hire/', views.hire, name='hire'),
    path('contact/', views.contact, name='contact'),
    path('editprofile/', views.profile_edit_view, name='editprofile'),
    path('register/', views.register_user, name='register'),
    path('', views.login, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout, name='logout'),
    path('update-member/', views.update_member, name='update_member'),
    path('get-member/<int:member_id>/', views.get_member, name='get_member'),
    path('submit-hire', views.submit_hire, name='submit_hire'),
    path('login/', views.login, name='login'),
    path('hireset/', views.hire_list, name='hireset'),  # URL สำหรับหน้า Hire List
    path('adminhires/', views.hireA_list, name='adminhires'),
    path('report/', views.Report_list, name='reports'),
    path('delete-member/<int:member_id>/', views.delete_member, name='delete_member'),
    path('check-duplicate/', views.check_duplicate, name='check_duplicate'),
    path('delete-hire/<int:hire_id>/', views.delete_hire, name='delete_hire'),
    path('api/hire/<int:hire_id>/', views.get_hire_details, name='get_hire_details'),
    path('api/predictC/<int:predict_id>/', views.get_predict_detailsC, name='get_predict_detailsC'),
    path('update-hire-status/<int:hire_id>/', views.update_hire_status, name='update_hire_status'),
    path('predictcustom/', views.predictcustom, name='predictcustom'),
    path('hires/filter/', filter_hire_by_date, name='filter_hire_by_date'),
    path('report/', views.report, name='report'),
    path('predict/', views.prediction, name='predict'),
    path('submit_hireA/', views.submit_hireA, name='submit_predictA'),
    path("download-pdf/", generate_pdf, name="download_pdf"),
    path("submit_success/", views.submit_success_hire, name="submit_success_hire"),
    path('delete-hireA/<int:hire_id>/', views.delete_hireA, name='delete_hireA'),
    path('api/hireA/<int:hire_id>/', views.get_hireA_details, name='get_hireA_details'),
    path('api/predictA/<int:predict_id>/', views.get_predict_detailsA, name='get_predict_detailsA'),
    path('update-hire-statusA/<int:hire_id>/', views.update_hireA_status, name='update_hireA_status'),
    path('hiresA/filter/', filter_hireA_by_date, name='filter_hireA_by_date'),
    path("get_resource_data/", get_resource_data, name="get_resource_data"),
]   + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
 