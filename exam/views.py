from django.shortcuts import render
from .serializers import (UserSerializer, QuestionSerializer, ExamSerializer, 
                          RegularUserLoginSerializer, AdminRegistrationSerializer,
                          AdminLoginSerializer, AddQuestionstoExamSerializer,
                          ChangePasswordSerializer,ResetPasswordEmailSerializer,ResetPasswordSerializer,CheckOTPSerializer,
                          UserProfileSerializer, UserResponseSerializer)
from rest_framework.generics import CreateAPIView, ListCreateAPIView, RetrieveDestroyAPIView, GenericAPIView, RetrieveAPIView, ListAPIView
from .models import Questions, Exam, Otp, UserProfile, PurchasedDate, UserResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAdminUser
from django.utils import timezone
from django.contrib.auth import update_session_auth_hash
from .services import add_question, otpgenerator, Utils, checkOTP, deleteOTP
from django.db import transaction
from django.contrib.auth.models import User
import logging
logger = logging.getLogger(__name__)


#user registration view.need to add token authentication, login while registration. and also need to create login view.
class UserRegistration(CreateAPIView):
    serializer_class = UserSerializer
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = serializer.save()
            # Logging in the user after successful registration
            login(request, user)
            # Generating or retrieving the token for the logged-in user
            token, created = Token.objects.get_or_create(user=user)
            response = {
                'data': serializer.data,
                'token': token.key,
                'status': status.HTTP_201_CREATED
            }
            return Response(response, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

#Regular User login view.
class RegularUserLoginView(APIView):
    serializer_class = RegularUserLoginSerializer

    def post(self, request):
        serializer = RegularUserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(request, username=serializer.data['username'], password=serializer.data['password'])
        if user is not None and not user.is_anonymous:
            # Invalidate all sessions except for the current one
            active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
            for session in active_sessions:
                session_data = session.get_decoded()
                if str(user.pk) == session_data.get('_auth_user_id'):
                    Token.objects.filter(user=user).delete()
                    session.delete()
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            print(token)
            response = {'message': 'Login Successful', 'token': token.key}
            return Response(response)
        
        return Response('The username or password is incorrect')


#Regular user logout view.
class RegularUserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    def post(self, request):
        # Delete the token associated with the user
        Token.objects.filter(user=request.user).delete()
        logout(request)
        response = {'message': 'You have been successfully logged out.'}
        return Response(response)


#Admin Registration view.
class AdminRegistrationView(CreateAPIView):
    serializer_class = AdminRegistrationSerializer


#Admin Login View.
#Authentication using django default authentication system.
class AdminLoginView(APIView):
    serializer_class = AdminLoginSerializer
    def post(self, request):
        serializer = AdminLoginSerializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        user = authenticate(request, username = serializer.data['username'], password = serializer.data['password'])
        if user is not None and user.is_superuser:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            response = {'message': 'Login Successful','token': token.key}
            return Response(response)
        return Response('The username or password is incorrect')


#Admin Logout View.
#endpoint can only be accessed if the user has authentication permission.
class AdminLogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request):
        if request.user.is_superuser:
            Token.objects.filter(user=request.user).delete()
            logout(request)
            response = {'message': 'You have been successfully logged out.'}
            return Response(response)
        else:
            return Response("invalid access")
        

#Admin accessible views.
#View to create and List created Questions.
class QuestionListCreateAPIView(ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = QuestionSerializer
    queryset = Questions.objects.all()
    
#View to Look Questions in detail and Delete created Questions.
class QuestionRetrieveDestroyAPIView(RetrieveDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = QuestionSerializer
    queryset = Questions.objects.all()
    lookup_field = 'id'

#View to create and List created Exams.
class ExamListCreateAPIView(ListCreateAPIView):
    Authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = ExamSerializer
    queryset = Exam.objects.all()

#View to Look Questions in detail and Delete created Exams.
class ExamRetrieveDestroyAPIView(RetrieveDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = ExamSerializer
    queryset = Exam.objects.all()
    lookup_field = 'exam_id'

#continue from checking the syntax of data is stored in db inorder to create a automatically question adding function.

class AddQuestionstoExam(APIView):
    serializer_class = AddQuestionstoExamSerializer

    def post(self, request):
        serializer = AddQuestionstoExamSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)

        exam_id = request.data['exam_id']
        exams = Exam.objects.get(exam_id = exam_id)
        questions = Questions.objects.all()
        add_question(exams=exams, questions=questions)

        while exams.questions.count() != 20: #change the number according to the number of questions
            add_question(exams=exams, questions=questions)

        response = {'success':True,'message': 'Questions added successfully'}

        return Response(response, status=status.HTTP_200_OK)


#view to assign a exam to a user.
class AssignExam(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdminUser]
    def post(self, request):
        #get exam id and username of the user.
        username = request.data.get('username')
        exam_id = request.data.get('exam_id')
        
        #get associated user and exam
        try:
            exam = Exam.objects.get(exam_id = exam_id)
            print(exam)
            user = User.objects.get(username = username)
            print(user)
        except User.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        except Exam.DoesNotExist:
            return Response("Exam not found", status=status.HTTP_404_NOT_FOUND)
                
        duration = int(request.data.get('duration')) #duration in days
        
        date_of_purchase = timezone.now()
        expiration_date = date_of_purchase + timezone.timedelta(days=duration)

        user_profile, created = UserProfile.objects.get_or_create(user = user)
        user_profile.purchased_exams.add(exam)

        purchased_date = PurchasedDate.objects.create(user_profile=user_profile,
                                                      exam = exam, 
                                                        date_of_purchase=timezone.now(),
                                                        expiration_date = expiration_date)
        purchased_date.save()

        return Response("Exam purchased successfully", status=status.HTTP_200_OK)

# view to change password by user
class ChangePasswordView(APIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = ChangePasswordSerializer
    def post(self, request):
        serializer = ChangePasswordSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if user.check_password(serializer.data['old_password']):
            user.set_password(serializer.data['new_password'])
            user.save()
            update_session_auth_hash(request, user)
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)    


#view to Request OTP.
class PasswordResetRequest(GenericAPIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = ResetPasswordEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data['email']
        user = User.objects.filter(username=email).first()

        if user:
            with transaction.atomic():
                otp_record, created = Otp.objects.get_or_create(user=user)

                if not created:
                    # An OTP record already exists, delete it and create a new one
                    otp_record.delete()
                    otp_record = Otp.objects.create(user=user)

                otp = otpgenerator()
                otp_record.otp = otp
                otp_record.save()

                email_body = 'Hello,\n This is the one-time-password for password reset of your account\n' + otp
                data = {'email_body': email_body, 'to_email': user.username, 'email_subject': 'Reset your password'}
                try:
                    Utils.send_email(data)

                    return Response({'success': True, 'message': "OTP SENT SUCCESSFULLY"}, status=status.HTTP_200_OK)

                except Exception as e:
                    logger.error(str(e))
                    return Response({'error': 'An error occurred while sending the email.'},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            return Response({'success': False, 'message': "User Not Found"}, status=status.HTTP_404_NOT_FOUND)



#view to validate OTP
class CheckOTP(APIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = CheckOTPSerializer

    def post(self, request):
        serializer = CheckOTPSerializer(data = request.data)
        serializer.is_valid(raise_exception = True)

        otp = request.data['otp']
        user = request.user
        saved_otp = Otp.objects.get(user = user)
        
        if checkOTP(otp=otp, saved_otp_instance=saved_otp):
            saved_otp.otp_validated = True
            saved_otp.save()
            return Response({'success':True, 'message':"OTP VERIFICATION SUCCESSFULL"}, status=status.HTTP_200_OK)

        else:
            return Response({'success':False, 'message':"INVALID OTP"}, status=status.HTTP_400_BAD_REQUEST)
        

#View to reset password through OTP
class ResetPasswordView(APIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = ResetPasswordSerializer(data = request.data)
        serializer.is_valid(raise_exception = True)

        user = request.user
        otp_instance = Otp.objects.get(user = user)

        if otp_instance.otp_validated == True:
            password  = request.data['password']
            user.set_password(password)
            user.save()
            update_session_auth_hash(request, user)
            otp_instance.delete()
            
            return Response({'success':True, 'message':"Password Changed Succesfully"}, status=status.HTTP_200_OK)

        else:
            return Response({'success':False, 'message':"verify OTP First"}, status=status.HTTP_400_BAD_REQUEST)
        

#User Profile View.
class UserProfileView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = UserSerializer
    lookup_field = 'username'
    def get_queryset(self):
        # Only allow the user to access their own instance
        print(self.request.user)
        return User.objects.filter(username=self.request.user.username)

#show the purchased history.
class PurchaseHistoryView(ListAPIView):
    serializer_class = UserProfileSerializer
    lookup_field = 'username'
    def get_queryset(self): 
        return UserProfile.objects.filter(user = self.request.user)
    
#view to add ExamResponse of User.
class UserExamResponseAdd(APIView):
    # authentication_classes = [TokenAuthentication]
    # permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = request.user
        serializer = UserResponseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        exam_id = validated_data.get('exam_id')
        response_data = validated_data.get('response')
        marks_scored = validated_data.get('marks_scored', '00')
        
        try:
            user_response = UserResponse.objects.create(
                user=user,
                exam_id=exam_id,
                response=response_data,
                marks_scored=marks_scored,
            )

            response = {
                "message": "User response added successfully",
                'data': {
                    'exam_id': exam_id,
                    'response': response_data,
                    'marks_scored': marks_scored,
                },
                'status': status.HTTP_201_CREATED
            }
            return Response(response, status=status.HTTP_201_CREATED)

        except:
            return Response("User not found", status=status.HTTP_401_UNAUTHORIZED)
