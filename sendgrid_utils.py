import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import sendgrid
from django.conf import settings


def send_otp_via_sendgrid(recipient_email, otp_code):
    """
    Sends an OTP code to the specified recipient using SendGrid.
    Ensure that you have set the SENDGRID_API_KEY in your environment or .env file.
    """
    message = Mail(
        from_email='admin@cryptguardsecurity.com',  # Replace with your verified sender email.
        to_emails=recipient_email,
        subject='Your OTP Code for CryptGuard',
        plain_text_content=f'Your OTP code is: {otp_code}',
    )
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        # Optional: print response details for debugging.
        print("OTP email sent, status code:", response.status_code)
    except Exception as e:
        print("Error sending OTP email:", e)

def send_verification_email(recipient_email, verification_url):
    sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
    subject = "Verify your email for CryptGuard"
    content = f"""
    Hi,

    Thank you for registering at CryptGuard.
    Please click the link below to verify your email address and activate your account:

    {verification_url}

    If you did not register at CryptGuard, please ignore this email.

    Best regards,
    The CryptGuard Team
    """
    message = Mail(
        from_email=settings.DEFAULT_FROM_EMAIL,  # Make sure to define this in your settings
        to_emails=recipient_email,
        subject=subject,
        plain_text_content=content
    )
    try:
        response = sg.send(message)
        # Optionally log the response status and body
    except Exception as e:
        # Log error
        print(e)