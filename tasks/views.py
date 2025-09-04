from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.http import urlsafe_base64_decode

from .models import Task,Profile
from django.contrib.auth import login,logout,authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
# Create your views here.
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.shortcuts import render, redirect
from django.contrib.auth.forms import PasswordResetForm
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import login
@login_required()
def tasks_page(request):
    tasks=Task.objects.filter(user=request.user)
    return render(request,"tasks/tasks.html",{"tasks": tasks})
@login_required()
def add_task(request):
    if request.method=='POST':
        title=request.POST.get('title')
        description=request.POST.get('description')
        deadline=request.POST.get('deadline')
        status=request.POST.get('status')

        Task.objects.create(
            title=title,
            description=description,
            deadline=deadline,
            status=status,
            user=request.user
        )
        return redirect('home')
    return render(request,"tasks/add_task.html")
@login_required()
def edit_task(request,uuid):
    task = get_object_or_404(Task,uuid=uuid,user=request.user)
    if request.method == 'POST':
        task.title = request.POST.get('title')
        task.description = request.POST.get('description')
        task.deadline = request.POST.get('deadline')
        task.status = request.POST.get('status')
        task.save()
        return redirect('home')
    return render(request,"tasks/edit_task.html",{'task':task})
@login_required()
def delete_task(request,uuid):
    task=get_object_or_404(Task,uuid=uuid,user=request.user)
    task.delete()
    return redirect('home')

def sign_in(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                context = {'error': 'Invalid username or password'}
                return render(request, "tasks/login.html", context)
        else:
            context = {'error': 'Please enter both username and password'}
            return render(request, "tasks/login.html", context)

    return render(request, "tasks/login.html")

def sign_up(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        profile_pic = request.FILES.get('profile_pic')  # optional

        # ✅ Password match check
        if password != password2:
            context = {'error': ['Passwords do not match']}
            return render(request, 'tasks/register.html', context)

        # ✅ Email format validation
        try:
            validate_email(email)
        except ValidationError as e:
            context = {'error': e.messages}
            return render(request, 'tasks/register.html', context)

        # ✅ Check if email already exists
        if User.objects.filter(email=email).exists():
            context = {'error': ['This email is already registered. Please log in instead.']}
            return render(request, 'tasks/register.html', context)

        # ✅ Password strength validation
        try:
            validate_password(password)
        except ValidationError as e:
            context = {'error': e.messages}
            return render(request, 'tasks/register.html', context)

        # ✅ Check if username already exists
        if User.objects.filter(username=username).exists():
            context = {'error': ['This username is already taken. Please choose another.']}
            return render(request, 'tasks/register.html', context)

        # ✅ Create user with hashed password
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )
        Profile.objects.create(
            user=user,
            image=profile_pic
        )

        # 🚀 Don’t auto-login, just show confirmation page
        return redirect('account_created')

    return render(request, "tasks/register.html")

def account_created(request):
    return render(request,"tasks/successful_account.html")

@login_required()
def sign_out(request):
    logout(request)
    return redirect('sign_in')

@login_required
def profile(request):
    # Ensure the profile exists
    profile, created = Profile.objects.get_or_create(user=request.user)
    user = request.user

    if request.method == 'POST':
        action = request.POST.get('action')  # identify which form was submitted

        # ================= Update Username =================
        if action == 'update_username':
            username = request.POST.get('username')
            if username and username != user.username:
                if User.objects.filter(username=username).exclude(pk=user.pk).exists():
                    messages.error(request, "This username is already taken.")
                else:
                    user.username = username
                    user.save()
                    messages.success(request, "Username updated successfully.")
            return redirect('profile')

        # ================= Update Password =================
        elif action == 'update_password':
            old_password = request.POST.get('old_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if not check_password(old_password, user.password):
                messages.error(request, "Old password is incorrect.")
            elif new_password != confirm_password:
                messages.error(request, "New password and confirm password do not match.")
            else:
                try:
                    validate_password(new_password, user)
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)  # keep user logged in
                    messages.success(request, "Password updated successfully.")
                except ValidationError as e:
                    for msg in e.messages:
                        messages.error(request, msg)
            return redirect('profile')

        # ================= Update Profile Image =================
        elif action == 'update_image':
            image = request.FILES.get('image')
            if image:
                # Delete old image if it exists and is not default
                if profile.image and profile.image.name != 'default.png':
                    profile.image.delete(save=False)

                profile.image = image
                profile.save()
                messages.success(request, "Profile image updated successfully.")
            return redirect('profile')

    return render(request, 'tasks/profile.html')


def reset_password(request):
    if request.method=="POST":
        email = request.POST.get("email", "").strip()
        if User.objects.filter(email__iexact=email).exists():
            form = PasswordResetForm(data={"email": email})
            if form.is_valid():
                form.save(
                    request=request,
                    use_https=request.is_secure(),
                    from_email="no-reply@taskly.com",
                    email_template_name="tasks/password_reset_email.html",
                    subject_template_name="tasks/password_reset_subject.txt"
                )
                return redirect('reset_confirm')  # redirect only after successful save
            else:
                context = {'error': ['Something went wrong while sending reset email.']}
                return render(request, "tasks/password_reset.html", context)
        else:
            context = {'error': ['This email is not registered. Please try with registered email.']}
            return render(request, "tasks/password_reset.html", context)

    return render(request,"tasks/password_reset.html")


def reset_confirm(request):
    return render(request,"tasks/reset_confirmation.html")

def password_changed(request):
    return render(request,"tasks/password_changed.html")

def set_new_password(request, uidb64, token):
    context = {}

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        context["error"] = "Invalid reset link."

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == "POST":
            password1 = request.POST.get("new_password1")
            password2 = request.POST.get("new_password2")

            if not password1 or not password2:
                context["error"] = "Both password fields are required."
            elif password1 != password2:
                context["error"] = "Passwords do not match."
            else:
                user.set_password(password1)
                user.save()
                login(request, user)
                return redirect("password_changed")
    else:
        if "error" not in context:
            context["error"] = "Invalid or expired reset link."

    return render(request, "tasks/set_new_password.html", context)
