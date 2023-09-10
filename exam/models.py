from django.db import models
from .services import CustomDuration
from django.utils.text import slugify
from django.contrib.auth.models import User
from django.utils import timezone
# Create your models here.


class Questions(models.Model):
    id = models.BigAutoField(unique=True, primary_key=True)
    questions_text = models.TextField(blank=True, null=True)
    questions_image = models.ImageField(upload_to='images/', blank=True, null=True) #need to specify the destination in settings.py
    optionA_text = models.TextField(blank=True, null=True)
    optionA_image = models.ImageField(upload_to='images/', blank=True, null=True)
    optionB_text = models.TextField(blank=True, null=True)
    optionB_image = models.ImageField(upload_to='images/', blank=True, null=True)
    optionC_text = models.TextField(blank=True, null=True)
    optionC_image = models.ImageField(upload_to='images/', blank=True, null=True)
    optionD_text = models.TextField(blank=True, null=True)
    optionD_image = models.ImageField(upload_to='images/', blank=True, null=True)
    choose = (('A', 'optionA'), ('B', 'optionB'), ('C', 'optionC'), ('D', 'optionD'))
    answer = models.CharField(max_length=1,choices=choose)
    solution_text = models.TextField(blank=True, null=True, editable=False)
    solution_image = models.ImageField(upload_to='images/', blank=True, null=True, editable=False)
    
 
    def save(self, *args, **kwargs):
        # Automatically set the solution based on the answer
        option_number = self.answer[-1]  # Extract the option number from 'optionX'
        option_text = getattr(self, f'option{option_number}_text')
        option_image = getattr(self, f'option{option_number}_image')
        
        if option_image:  # If option is an image
            self.solution_image = f'Option {option_number}: Image - {option_image.url}' #
        else:  # If option is text
            self.solution_text = f'Option {option_number}: {option_text}'
        
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{id}"


class Exam(models.Model):
    id = models.BigAutoField(unique=True, primary_key=True)
    exam_id = models.CharField(unique=True,max_length = 6)
    exam_name = models.CharField(max_length=150)
    duration = CustomDuration()
    instructions = models.TextField()
    questions = models.ManyToManyField(Questions, related_name='questions', blank=True)
    total_marks = models.PositiveIntegerField()
    qualify_score = models.PositiveIntegerField()
    is_active = models.BooleanField(default=True, help_text="Make Sure to Set Active-state while creating.")
    created_date = models.DateTimeField(auto_now_add=True, blank=True)
    updated_date =  models.DateTimeField(auto_now=True, blank=True)
    slug_exam = models.SlugField(blank=True)

    def save(self, *args, **kwargs):
        if not self.slug_exam:
            self.slug_exam = slugify(self.exam_name)
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.exam_id}:{self.exam_name}"

    
# models to store otp
class Otp(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_validated = models.BooleanField(default=False, blank=True)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_profile', null=True, blank=True)
    purchased_exams = models.ManyToManyField(Exam, blank=True, related_name='purchased_exams')

    def __str__(self) -> str:
        return f"{self.user}"
    
class PurchasedDate(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='purchased_dates')
    exam = models.ForeignKey(Exam, on_delete=models.CASCADE, related_name='purchased_dates', null=True, blank=True)
    date_of_purchase = models.DateTimeField(default=timezone.now)
    expiration_date = models.DateTimeField()

    def __str__(self) -> str:
        return f"PurchasedDate for {self.user_profile}, Exam: {self.exam}"
    
class UserResponse(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='userresponse')
    exam_id = models.CharField(max_length=50)
    response = models.JSONField(default=dict)
    marks_scored = models.CharField(max_length=4, default='00')
    #  {
    # "1": "A",
    # "2": "C",
    # "3": "B"
    # }
    def __str__(self) -> str:
        return f"{self.userprofile.username}-{self.exam_id}"