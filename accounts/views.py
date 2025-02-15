import pyotp
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.views import View
from django.contrib import messages
from django.utils import timezone
from django.views.generic.edit import FormView, UpdateView
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import User
from .forms import  CustomUserCreationForm, LoginForm, OTPForm, ChangeNameForm, PasswordResetRequestForm, OTPPasswordResetForm

User = get_user_model()

class SignupView(FormView):
    template_name = 'accounts/register.html'
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('homepage')  # Redirect to dashboard after signup

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
    
def logout_view(request):
    logout(request)  # This will log the user out.
    return redirect('homepage')  # Redirect to a page after logout (e.g., homepage)
    

class CombinedLoginView(View):
    template_name = 'accounts/login_and_otp.html'
    
    def get(self, request):
        # Initially, display only the login form.
        login_form = LoginForm()
        otp_form = OTPForm()  # This can be hidden initially in the template.
        return render(request, self.template_name, {
            'login_form': login_form,
            'otp_form': otp_form,
            'stage': 1,  # Stage 1: login credentials only.
        })
    
    def post(self, request):
        # If 'otp' is in POST data, then this is Stage 2.
        if 'otp' in request.POST:
            otp_form = OTPForm(request.POST)
            # We assume login_form is still needed for context; you can pass it if desired.
            login_form = LoginForm()
            if otp_form.is_valid():
                otp_input = otp_form.cleaned_data['otp']
                # Retrieve stored data from session
                user_id = request.session.get('otp_user_id')
                otp_secret = request.session.get('otp_secret')
                if not user_id or not otp_secret:
                    messages.error(request, "Session expired. Please log in again.")
                    return redirect('accounts:login')
                totp = pyotp.TOTP(otp_secret, interval=300)  # OTP valid for 5 minutes
                if totp.verify(otp_input, valid_window=1):
                    # OTP verified: log the user in.
                    user = User.objects.get(id=user_id)
                    login(request, user)
                    # Clean up session data
                    request.session.pop('otp_user_id', None)
                    request.session.pop('otp_secret', None)
                    return redirect(reverse_lazy('homepage'))
                else:
                    messages.error(request, "Invalid OTP. Please try again.")
                    # Render with stage 2 (showing OTP field)
                    return render(request, self.template_name, {
                        'login_form': login_form,
                        'otp_form': otp_form,
                        'stage': 2,
                    })
            else:
                messages.error(request, "Please enter a valid OTP.")
                return render(request, self.template_name, {
                    'login_form': login_form,
                    'otp_form': otp_form,
                    'stage': 2,
                })
        else:
            # Stage 1: Process login credentials.
            login_form = LoginForm(request.POST)
            if login_form.is_valid():
                email = login_form.cleaned_data['email']
                password = login_form.cleaned_data['password']
                user = authenticate(request, username=email, password=password)
                if user is not None:
                    # Credentials are valid.
                    # Generate an OTP secret and code.
                    otp_secret = pyotp.random_base32()
                    totp = pyotp.TOTP(otp_secret, interval=300)
                    otp_code = totp.now()
                    
                    # Store OTP details in session for Stage 2 verification.
                    request.session['otp_user_id'] = str(user.id)
                    request.session['otp_secret'] = otp_secret
                    
                    # Send OTP using SendGrid.
                    from sendgrid_utils import send_otp_via_sendgrid
                    send_otp_via_sendgrid(user.email, otp_code)
                    
                    messages.info(request, "An OTP has been sent to your email. Please enter it below.")
                    # Render the same template now showing the OTP form.
                    otp_form = OTPForm()
                    return render(request, self.template_name, {
                        'login_form': login_form,
                        'otp_form': otp_form,
                        'stage': 2,
                    })
                else:
                    messages.error(request, "Invalid email or password.")
            # If login form is not valid or authentication fails:
            otp_form = OTPForm()  # Provide an empty OTP form for context.
            return render(request, self.template_name, {
                'login_form': login_form,
                'otp_form': otp_form,
                'stage': 1,
            })
        
#dashboard view
@login_required
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html')

class ChangeNameView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = ChangeNameForm
    template_name = 'accounts/change_name.html'
    success_url = reverse_lazy('accounts:dashboard')  # Adjust if your dashboard URL name is different

    def get_object(self, queryset=None):             # Ensure the user can only change their own name
            return self.request.user
    

class PasswordResetView(View):
    template_name = "accounts/password_reset.html"
    
    def get(self, request):
        # Determine stage: if OTP was sent, show OTP form; otherwise, show email form.
        if request.session.get('reset_otp_sent'):
            form = OTPPasswordResetForm()
            stage = 2
        else:
            form = PasswordResetRequestForm()
            stage = 1
        return render(request, self.template_name, {"form": form, "stage": stage})
    
    def post(self, request):
        # Stage 2: If session indicates OTP has been sent, process OTP and new password.
        if request.session.get('reset_otp_sent'):
            form = OTPPasswordResetForm(request.POST)
            if form.is_valid():
                otp_input = form.cleaned_data["otp"]
                new_password = form.cleaned_data["new_password1"]
                otp_secret = request.session.get("reset_otp_secret")
                user_id = request.session.get("reset_user_id")
                if not otp_secret or not user_id:
                    messages.error(request, "Session expired. Please request a new OTP.")
                    return redirect("accounts:password_reset")
                totp = pyotp.TOTP(otp_secret, interval=300)  # OTP valid for 5 minutes
                if totp.verify(otp_input, valid_window=1):
                    # OTP is valid, update the password.
                    user = User.objects.get(id=user_id)
                    user.set_password(new_password)
                    user.save()
                    # Clear session data
                    request.session.pop("reset_otp_sent", None)
                    request.session.pop("reset_otp_secret", None)
                    request.session.pop("reset_user_id", None)
                    messages.success(request, "Your password has been updated successfully!")
                    return redirect(reverse_lazy("accounts:login"))
                else:
                    messages.error(request, "Invalid OTP. Please try again.")
                    return render(request, self.template_name, {"form": form, "stage": 2})
            else:
                messages.error(request, "Please correct the errors below.")
                return render(request, self.template_name, {"form": form, "stage": 2})
        else:
            # Stage 1: Process email to send OTP.
            form = PasswordResetRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data["email"]
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    messages.error(request, "No user found with that email.")
                    return render(request, self.template_name, {"form": form, "stage": 1})
                
                # Generate an OTP secret and code.
                otp_secret = pyotp.random_base32()
                totp = pyotp.TOTP(otp_secret, interval=300)
                otp_code = totp.now()
                
                # Store OTP details in session for Stage 2.
                request.session["reset_user_id"] = str(user.id)
                request.session["reset_otp_secret"] = otp_secret
                request.session["reset_otp_sent"] = True

                # Send OTP via SendGrid.
                from sendgrid_utils import send_otp_via_sendgrid
                send_otp_via_sendgrid(user.email, otp_code)
                
                messages.info(request, "An OTP has been sent to your email. Please enter it along with your new password.")
                form = OTPPasswordResetForm()
                return render(request, self.template_name, {"form": form, "stage": 2})
            else:
                messages.error(request, "Please correct the errors below.")
                return render(request, self.template_name, {"form": form, "stage": 1})