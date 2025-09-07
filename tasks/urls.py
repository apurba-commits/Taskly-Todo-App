from django.contrib import admin
from django.urls import path, include, reverse_lazy
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
urlpatterns = [
    path('dashboard/',views.tasks_page,name='home'),
    path('add_task/',views.add_task,name='add_task'),
    path('edit/<uuid:uuid>/',views.edit_task,name='edit_task'),
    path('delete/<uuid:uuid>/',views.delete_task,name='delete_task'),
    path('',views.sign_in,name='sign_in'),
    path('register/',views.sign_up,name='sign_up'),
    path('successfully_created/',views.account_created,name='account_created'),
    path('profile/', views.profile, name='profile'),
    path('logout/',views.sign_out,name='sign_out'),
    path('reset/',views.reset_password,name='reset_password'),
    path('reset_confirm',views.reset_confirm,name='reset_confirm'),
    path('reset/<uidb64>/<token>/',views.set_new_password,name='password_reset_confirm'),
    path('password_changed/',views.password_changed,name='password_changed')
]
