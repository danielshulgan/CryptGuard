from django.contrib.auth import login
from django.contrib import messages
from django.utils import timezone
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from .forms import  CustomUserCreationForm

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