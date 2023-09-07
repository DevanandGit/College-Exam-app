#All logical functions and inheritance are implemented here.
from django.db.models import DurationField
import random
from rest_framework.response import Response

class CustomDuration(DurationField):
    def format_duration(self, duration):
        formatted_duration = super().format_duration(duration)
        hours, minutes, seconds = formatted_duration.split(":")
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
def add_question(exams, questions):
    total = 20 #change the number according to the number of questions
    no_of_questions = exams.questions.count()
    no_of_ques_to_add = total-no_of_questions

    for i in range(no_of_ques_to_add):
        test = random.choice(questions)
        exams.questions.add(test)


#method to send mail.
class Utils:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to = [data['to_email']])
        email.send()
        return Response('Email sent successfully!')
    
#method to generate OTP
def otpgenerator():
    rand_no = [x for x in range(10)]
    code_items_for_otp = []

    for i in range(6):
        num = random.choice(rand_no)
        code_items_for_otp.append(num)
        code_string = "".join(str(item) for item in code_items_for_otp)

    return code_string

#method to validate OTP
def checkOTP(otp, saved_otp_instance):
    if saved_otp_instance.otp == otp:
        return True
    else:
        return False
        

#method to delete OTP
def deleteOTP(saved_otp_instance):
    saved_otp_instance.delete()
    
