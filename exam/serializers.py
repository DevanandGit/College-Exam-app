from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Exam, Questions


#serializer to validate the userregistration data.
class UserSerializer(serializers.ModelSerializer):
    password = serializers.RegexField(
        regex=r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        max_length=128,
        min_length=8,
        write_only=True,
        error_messages={
            'invalid': 'Password must contain at least 8 characters, including uppercase, lowercase, and numeric characters.'
        }
    )

    confirm_password = serializers.CharField(write_only=True)

    username = serializers.RegexField(regex='PRP', help_text = 'Username should be your college reg-number starting with PRP')

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email','password', 'confirm_password']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError('Password Mismatch')
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            username = validated_data['username'],
            password = validated_data['password']
        )
        return user


#validate data of regular user login.
class RegularUserLoginSerializer(serializers.Serializer):
    username = serializers.EmailField()
    password = serializers.CharField(max_length=128)


#validate data for admin creation.
class AdminRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.RegexField(
        regex=r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        max_length=128,
        min_length=8,
        write_only=True,
        error_messages={
            'invalid': 'Password must contain at least 8 characters, including uppercase, lowercase, and numeric characters.'
        }
    )
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'username', 'password', 'confirm_password']
        default_related_name = 'admin_users'

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError('Password mismatch')
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_superuser(
            username=validated_data['username'],
            password=validated_data['password'],
            name=validated_data['name']
        )
        return user
    

#validate data for admin login.
class AdminLoginSerializer(serializers.Serializer):
    username = serializers.EmailField()
    password = serializers.CharField(max_length=128)
        

class ExamSerializer(serializers.ModelSerializer):

    class Meta:
        model = Exam
        fields = ['id', 'exam_id','exam_name', 'duration', 'instructions', 'questions', 'total_marks', 'qualify_score', 'is_active', 'created_date', 'updated_date']

class QuestionSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Questions
        fields = ['id', 'questions_text', 'questions_image', 'optionA_text', 'optionA_image', 'optionB_text', 'optionB_image', 'optionC_text', 'optionC_image', 'optionD_text', 'optionD_image', 'choose', 'answer', 'solution_text', 'solution_image']
    
class AddQuestionstoExamSerializer(serializers.Serializer):
    exam_id = serializers.CharField(max_length = 6, min_length = 6)


# validates the password entered for changing password.
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        fields = ['old_password','new_password', 'confirm_password']

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError('Password mismatch')
        return data

#valildates the email entered for sending otp.
class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    class Meta:
        fields = ['email']

# validates the password entered for changing password.
class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.RegexField(
        regex=r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        max_length=128,
        min_length=8,
        write_only=True,
        error_messages={
            'invalid': 'Password must contain at least 8 characters, including uppercase, lowercase, and numeric characters.'
        }
    )
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password','confirm_password']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError('password mismatch')
        return data
        
#validates if the otp entered is correct.
class CheckOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length = 6, max_length = 6)