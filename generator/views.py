import string
import secrets
from django.http import JsonResponse

def generate_password(request):
    try:
        # Get desired length from query parameters, default to 12 if not provided
        length = int(request.GET.get('length', 12))
    except ValueError:
        length = 12

    # Define the character set: letters, digits, and punctuation.
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Optionally, remove ambiguous characters if desired.

    # Generate the password using the secrets module for security.
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return JsonResponse({'password': password})
