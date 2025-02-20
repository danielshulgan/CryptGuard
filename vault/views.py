from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from .models import VaultItem
from .forms import VaultItemForm

class VaultItemListView(LoginRequiredMixin, ListView):
    model = VaultItem
    template_name = 'vault/vault_list.html'
    context_object_name = 'items'
    
    def get_queryset(self):
        return VaultItem.objects.filter(user=self.request.user)

class VaultItemCreateView(LoginRequiredMixin, CreateView):
    model = VaultItem
    form_class = VaultItemForm
    template_name = 'vault/vault_item_form.html'
    success_url = reverse_lazy('vault:vault_list')

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)

class VaultItemUpdateView(LoginRequiredMixin, UpdateView):
    model = VaultItem
    form_class = VaultItemForm
    template_name = 'vault/vault_item_form.html'
    success_url = reverse_lazy('vault:vault_list')

    def get_queryset(self):
        return VaultItem.objects.filter(user=self.request.user)

class VaultItemDeleteView(LoginRequiredMixin, DeleteView):
    model = VaultItem
    template_name = 'vault/vault_item_confirm_delete.html'
    success_url = reverse_lazy('vault:vault_list')

    def get_queryset(self):
        return VaultItem.objects.filter(user=self.request.user)