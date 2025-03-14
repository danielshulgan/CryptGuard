import string
import secrets
from django.http import JsonResponse

def generate_password(request):
    try:
        length = int(request.GET.get('length', 12))
    except ValueError:
        length = 12

    # Check if the user wants to include special characters (default is True)
    include_special = request.GET.get('include_special', 'true').lower() in ['true', '1', 'yes']

    if include_special:
        alphabet = string.ascii_letters + string.digits + string.punctuation
    else:
        alphabet = string.ascii_letters + string.digits

    # Generate the password using the secrets module for security.
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return JsonResponse({'password': password})