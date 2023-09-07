# Generated by Django 4.1.7 on 2023-09-06 16:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('exam', '0003_alter_questions_questions_text'),
    ]

    operations = [
        migrations.RenameField(
            model_name='questions',
            old_name='solution',
            new_name='solution_text',
        ),
        migrations.AddField(
            model_name='questions',
            name='solution_image',
            field=models.ImageField(blank=True, editable=False, null=True, upload_to='images/'),
        ),
    ]