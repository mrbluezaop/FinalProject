# 
echo "⚙️ Running makemigrations..."
python manage.py makemigrations --noinput || echo "⚠️ Skipping makemigrations"

echo "⚙️ Running migrations..."
python manage.py migrate --noinput || echo "⚠️ Skipping migrations"

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput || echo "⚠️ Skipping collectstatic"

echo "✅ Running Django..."
exec gunicorn --bind 0.0.0.0:8000 myproject.wsgi:application
