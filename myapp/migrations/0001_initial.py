# Generated by Django 5.1.3 on 2024-12-25 09:57

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Member',
            fields=[
                ('Customer_ID', models.AutoField(primary_key=True, serialize=False)),
                ('Username', models.CharField(max_length=20, unique=True)),
                ('Firstname', models.CharField(max_length=100)),
                ('Lastname', models.CharField(max_length=100)),
                ('Password', models.CharField(max_length=100)),
                ('Email', models.EmailField(max_length=100, unique=True)),
                ('Phone', models.CharField(max_length=10)),
                ('Address', models.CharField(max_length=100)),
                ('Birthday', models.DateField(blank=True, null=True)),
                ('joined_date', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
