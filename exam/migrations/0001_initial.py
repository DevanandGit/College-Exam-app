# Generated by Django 4.1.7 on 2023-09-06 15:32

from django.db import migrations, models
import exam.services


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Questions',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False, unique=True)),
                ('questions_text', models.TextField()),
                ('questions_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('option1_text', models.TextField(blank=True, null=True)),
                ('option1_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('option2_text', models.TextField(blank=True, null=True)),
                ('option2_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('option3_text', models.TextField(blank=True, null=True)),
                ('option3_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('option4_text', models.TextField(blank=True, null=True)),
                ('option4_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('answer', models.CharField(choices=[('A', 'option1'), ('B', 'option2'), ('C', 'option3'), ('D', 'option4')], max_length=1)),
                ('solution', models.TextField(blank=True, editable=False, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Exam',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False, unique=True)),
                ('exam_id', models.PositiveIntegerField(unique=True)),
                ('exam_name', models.CharField(max_length=150)),
                ('duration', exam.services.CustomDuration()),
                ('instructions', models.TextField()),
                ('total_marks', models.PositiveIntegerField()),
                ('qualify_score', models.PositiveIntegerField()),
                ('is_active', models.BooleanField(default=True, help_text='Make Sure to Set Active-state while creating.')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('updated_date', models.DateTimeField(auto_now=True)),
                ('slug_exam', models.SlugField(blank=True)),
                ('questions', models.ManyToManyField(related_name='questions', to='exam.questions')),
            ],
        ),
    ]
