from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import redirect
from django.views.generic import TemplateView


class HomePageView(LoginRequiredMixin, TemplateView):
    template_name = 'layouts/homepage.html'  # Your homepage template
    login_url = '/create-account/'  # Redirect non-logged-in users here

class CreateAccountView(TemplateView):
    template_name = 'accounts/create_account.html'  # Your registration page template