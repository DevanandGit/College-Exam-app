from django.urls import path
from .views import (UserRegistration, RegularUserLoginView, RegularUserLogoutView, 
                    AdminRegistrationView, AdminLoginView, AdminLogoutView,
                    QuestionListCreateAPIView, QuestionRetrieveDestroyAPIView,ExamListCreateAPIView, 
                    ExamRetrieveDestroyAPIView, AddQuestionstoExam,
                    ChangePasswordView, PasswordResetRequest, CheckOTP, ResetPasswordView,
                    AssignExam, UserProfileView, PurchaseHistoryView, UserExamResponseAdd, 
                    QuestionTypeListCreateAPIView, QuestionTypeRetrieveDestroyAPIView, 
                    DifficultyLevelListCreateAPIView, DifficultyLevelRetrieveDestroyAPIView)

from .views import current_datetime
urlpatterns = [
    path('user-reg/', UserRegistration.as_view(), name = 'user-reg'),
    path('user-login/', RegularUserLoginView.as_view(), name = 'user-login'),
    path('user-logout/', RegularUserLogoutView.as_view(), name = 'user-logout'),

    path('admin-reg/', AdminRegistrationView.as_view(), name = 'admin-reg'),
    path('admin-login/', AdminLoginView.as_view(), name = 'admin-login'),
    path('admin-logout/', AdminLogoutView.as_view(), name = 'admin-logout'),

    path('question-add-list/', QuestionListCreateAPIView.as_view(), name='question-add-list'),
    path('question-add-list/<int:id>/', QuestionRetrieveDestroyAPIView.as_view(), name='question-retrieve-delete'),
    path('exam-add-list/', ExamListCreateAPIView.as_view(), name='exam-add-list'),
    path('exam-add-list/<str:exam_id>/', ExamRetrieveDestroyAPIView.as_view(), name='exam-retrieve-delete'),
    path('add-question-to-exam/', AddQuestionstoExam.as_view(), name = 'add-question-to-exam'),

    path('questiontype-add-list/', QuestionTypeListCreateAPIView.as_view(), name='questiontype-add-list'),
    path('questiontype-add-list/<int:id>/', QuestionTypeRetrieveDestroyAPIView.as_view(), name='questiontype-retrieve-delete'),
    path('difficulty_level-add-list/', DifficultyLevelListCreateAPIView.as_view(), name='difficulty_level-add-list'),
    path('difficulty_level-add-list/<int:id>/', DifficultyLevelRetrieveDestroyAPIView.as_view(), name='difficulty_level-retrieve-delete'),

    path('assign-exam/', AssignExam.as_view(), name = 'assign-exam'),
    path('current-datetime/', current_datetime, name='current_datetime'),

    path('userlist/<str:username>/', UserProfileView.as_view(), name='user_profile'),
    path('userlist/<str:username>/purchase_history/', PurchaseHistoryView.as_view(), name='purchase_history'),
    path('examresponseadd/', UserExamResponseAdd.as_view(), name='examresponseadd'),

    path('change_password/', ChangePasswordView.as_view(), name='change_password'), 
    path('otp-request/', PasswordResetRequest.as_view(), name='otp-request'),
    path('check-otp/', CheckOTP.as_view()),
    path('reset-password/', ResetPasswordView.as_view())
]
