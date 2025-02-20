from django.urls import path
from .views import VaultItemListView, VaultItemCreateView, VaultItemUpdateView, VaultItemDeleteView

app_name = 'vault'

urlpatterns = [
    path('', VaultItemListView.as_view(), name='vault_list'),
    path('add/', VaultItemCreateView.as_view(), name='vault_item_add'),
    path('<int:pk>/edit/', VaultItemUpdateView.as_view(), name='vault_item_edit'),
    path('<int:pk>/delete/', VaultItemDeleteView.as_view(), name='vault_item_delete'),
]