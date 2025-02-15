import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

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