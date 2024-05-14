from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeDoneView, PasswordChangeView, \
    PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.urls import path, include
from django.views.generic import TemplateView
from django.urls import reverse_lazy

from .views import Register, EmailVerify, UserProfileView, UsersListView, UserProfileEditView

app_name = 'users'

urlpatterns = [
    path('login/', LoginView.as_view(template_name='users/login.html'), name='login'),
    path(
        'invalid_verify/',
        TemplateView.as_view(template_name='users/invalid_verify.html'),
        name='invalid_verify'
    ),
    path(
        'verify_email/<uidb64>/<token>/',
        EmailVerify.as_view(),
        name='verify_email',
    ),
    path(
        'confirm_email/',
        TemplateView.as_view(template_name='users/confirm_email.html'),
        name='confirm_email'
    ),
    path('register/', Register.as_view(), name='register'),
    path(
        "password_change/",
        PasswordChangeView.as_view(template_name='users/password_change_form.html',
                                   success_url=reverse_lazy('users:password_change_done')),
        name="password_change"
    ),
    path(
        "password_change/done/",
        PasswordChangeDoneView.as_view(template_name='users/password_change_done.html'),
        name="password_change_done"
    ),
    path(
        "password_reset/",
        PasswordResetView.as_view(template_name='users/password_reset_form.html',
                                  email_template_name="users/password_reset_email.html",
                                  success_url=reverse_lazy("users:password_reset_done")),
        name="password_reset_form"
    ),
    path(
        "password_reset/done/",
        PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'),
        name="password_reset_done"
    ),
    path(
        "reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html',
                                         success_url=reverse_lazy("users:password_reset_complete")),
                                         name="password_reset_confirm"
                                         ),
        path("reset/done/", PasswordResetCompleteView.as_view(
            template_name='users/password_reset_complete.html'), name="password_reset_complete"),
        path('', include('django.contrib.auth.urls')),
        path('users_list/', UsersListView.as_view(), name='users_list'),
        path('<str:username>/', UserProfileView.as_view(), name='profile'),
        path('<str:username>/edit/', UserProfileEditView.as_view(), name='profile_edit'),
]
