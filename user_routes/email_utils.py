# -------------------- IMPORTS --------------------
import os
import re
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# -------------------- CONFIGURATION --------------------
SES_SENDER_EMAIL = os.environ["SES_SENDER_EMAIL"]
ses_client = boto3.client("ses")

# -------------------- HTML EMAIL TEMPLATE --------------------
HTML_TEMPLATE = """
<html>
<head>
  <style>
    body {
      font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #7AE2CF;
      color: #222831;
      margin: 0;
      padding: 0;
    }
    .container {
      background: #F3F3E0;
      width: 100%;
      max-width: 600px;
      margin: 40px auto;
      border-radius: 8px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.6);
      padding: 30px 40px;
    }
    h1 {
      font-size: 22px;
      color: #222831;
    }
    p {
      font-size: 15px;
      line-height: 1.6;
    }
    a.button {
      display: inline-block;
      margin-top: 20px;
      padding: 12px 22px;
      background-color: #2563eb;
      color: #ffffff;
      text-decoration: none;
      border-radius: 5px;
      font-weight: bold;
    }
    .footer {
      margin-top: 30px;
      font-size: 13px;
      color: #222831;
      font-weight: bold;
    }
    .username {
      font-weight: bold;
      color: #2563eb;
    }
  </style>
</head>
<body>
  <div class="container">

    <p>You have been invited to join at <strong> Timesheets </strong>.</p>

    <p>To sign in, first follow the link below to set up your password:</p>

    <a class="button" href="{{SETUP_LINK}}">Set your password</a>

    <p class="footer">
      Username: <span class="username">{{USER_EMAIL}}</span>
    </p>
  </div>
</body>
</html>
"""

# -------------------- RENDER EMAIL CONTENT --------------------
def render_invitation_email(setup_link: str, user_email: str, is_password_reset=False) -> str:
    email_template = HTML_TEMPLATE
    if is_password_reset:
        email_template = email_template.replace(
            "<p>You have been invited to join at <strong> Timesheets </strong>.</p>",
            "<p>We received a request to reset your Timesheets password.</p>"
        ).replace("Set your password", "Reset your password")

    return (
        email_template
        .replace("{{SETUP_LINK}}", setup_link)
        .replace("{{USER_EMAIL}}", user_email)
    )

# -------------------- SEND EMAIL VIA SES --------------------
def send_email(recipient: str, subject: str, html_body: str, text_body: str = None):
    if not text_body:
        text_body = re.sub(r"<[^>]+>", "", html_body)

    try:
        ses_client.send_email(
            Source=f"Timesheets <{SES_SENDER_EMAIL}>",
            Destination={"ToAddresses": [recipient]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Html": {"Data": html_body},
                    "Text": {"Data": text_body}
                }
            }
        )
    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to send email: {e}")
