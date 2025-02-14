from django.shortcuts import redirect, render, reverse
from django.contrib.auth import authenticate, login, get_user_model, logout
from django.contrib import messages
from django.views.generic.base import TemplateView
from django.utils import timezone
from django.views.generic.edit import FormView, View
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from .forms import PasswordResetForm, CustomUserCreationForm, EmailResetForm, UpdateNameForm
from otp_auth.models import OTP
from otp_auth.views import send_otp_via_sendgrid
import pyotp
from .forms import LoginForm


class LoginView(FormView):
    template_name = 'accounts/login.html'
    form_class = LoginForm

    def form_valid(self, form):
        # Cleaned data from the LoginForm
        email = form.cleaned_data.get('email').lower()
        password = form.cleaned_data.get('password')

        # Authenticate user using email as the username
        try:
            user = authenticate(self.request, username=email, password=password)
        except Exception as e:
            print(f"Authentication Error: {e}")
            user = None

        if user is not None:
            # Generate and save a new OTP
            otp_secret = pyotp.random_base32()
            otp = pyotp.TOTP(otp_secret)
            otp_code = otp.now()

            # Create or update the OTP object for the user
            otp_obj, created = OTP.objects.get_or_create(
                user=user,
                defaults={'email': user.email}
            )
            if not created:
            # Ensure the email is updated if necessary.
                otp_obj.email = user.email
            otp_obj.otp_secret = otp_secret
            otp_obj.is_verified = False
            otp_obj.save()

            # Send the OTP via email
            send_otp_via_sendgrid(user.email, otp_code)

            # Store the user's ID in the session for OTP verification
            self.request.session['otp_user_id'] = user.id

            # Redirect to the OTP verification page
            return redirect(reverse('otp_auth:verify_login_otp'))
        else:
            # If authentication fails, return the form with an error message
            messages.error(self.request, "Invalid email or password")
            return self.form_invalid(form)


def logout_view(request):
    logout(request)  # This logs out the user
    return redirect('/') 

class SignupView(FormView):
    template_name = 'accounts/register.html'
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('accounts:dashboard')  # Redirect to dashboard after signup

    def form_valid(self, form):
        # Save the user but don't commit to the database yet
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password1'])  # Hash the password
        user.is_signed_agreement = timezone.now()  # Set agreement time
        user.save()  # Save user to the database

        # Log the user in after signup
        login(self.request, user)
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the error below.")
        return super().form_invalid(form)

class DashboardView(TemplateView):
    template_name = 'accounts/dashboard.html'

@method_decorator(login_required, name='dispatch')
class ResetPasswordView(FormView):
    template_name = 'accounts/reset_password.html'
    form_class = PasswordResetForm
    success_url = reverse_lazy('accounts:dashboard')  # Redirect after successful password reset

    def dispatch(self, request, *args, **kwargs):
        # Check if 'reset_email' is in session, otherwise redirect to login
        if 'reset_email' not in request.session:
            return redirect('accounts:login')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        email = self.request.session.get('reset_email')
        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if user:
            # Set the new password
            new_password = form.cleaned_data['new_password']
            user.set_password(new_password)
            user.save()
            
            # Log the user in and clear the session
            login(self.request, user)
            self.request.session.pop('reset_email', None)

            return super().form_valid(form)  # Redirects to success_url
        else:
            # Redirect to login if user not found
            return redirect('accounts:login')
        
@method_decorator(login_required, name='dispatch')  # Ensure the user is logged in
class ChangeEmailView(FormView):
    template_name = 'accounts/update_email.html'  
    form_class = EmailResetForm  
    success_url = reverse_lazy('accounts:dashboard') 

    def form_valid(self, form):
        current_email = form.cleaned_data['current_email']
        new_email = form.cleaned_data['new_email']
        confirm_new_email = form.cleaned_data['confirm_new_email']
        
        user = get_user_model().objects.filter(email=current_email).first()

        if user:
            # Check if the new email matches the confirmation email
            if new_email == confirm_new_email:
                # Change the user's email
                user.email = new_email
                user.save()
                messages.success(self.request, "Your email address has been successfully updated.")
                return super().form_valid(form)
            else:
                form.add_error('confirm_new_email', "New email and confirmation email do not match.")
                return self.form_invalid(form)
        else:
            form.add_error('current_email', "Current email address not found.")
            return self.form_invalid(form)

    def form_invalid(self, form):
        messages.error(self.request, "There was an error updating your email address.")
        return super().form_invalid(form)
    

@method_decorator(login_required, name='dispatch')  # Ensure the user is logged in
class ChangeNameView(FormView):
    template_name = 'accounts/update_name.html'  
    form_class = UpdateNameForm  
    success_url = reverse_lazy('accounts:change_name') 

    def form_valid(self, form):
        user = self.request.user  # Get the currently logged-in user
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.save()  # Save the updated user information

        messages.success(self.request, "Your name has been successfully updated.")
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, "There was an error updating your name.")
        return super().form_invalid(form)