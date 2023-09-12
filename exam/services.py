#All logical functions and inheritance are implemented here.
from django.db.models import DurationField
import random
from rest_framework.response import Response

class CustomDuration(DurationField):
    def format_duration(self, duration):
        formatted_duration = super().format_duration(duration)
        hours, minutes, seconds = formatted_duration.split(":")
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
def add_question(exams, questions, questions_count):
    # for i in range(questions_count):
    #     test = random.choice(questions)
    #     exams.questions.add(test)

    # if exams.questions.count() != questions_count:
    #     remaining = questions_count - exams.questions.count()
    #     for i in range(remaining):
    #         test = random.choice(questions)
    #         exams.questions.add(test)
    question_ids = list(questions.values_list('id', flat=True))
    print(question_ids)
    # Shuffle the list of question IDs to randomize the selection
    random.shuffle(question_ids)
    
    questions_to_add = question_ids[:questions_count]
    print(f"questions to Add:{questions_to_add}")
    # Add selected questions to the exam
    exams.questions.add(*questions_to_add)


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
    
