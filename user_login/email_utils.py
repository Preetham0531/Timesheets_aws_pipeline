# -------------------- IMPORTS --------------------
import os
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from utils import get_user_full_name

# -------------------- ENVIRONMENT & CLIENT SETUP --------------------
SES_SENDER_EMAIL = os.environ["SES_SENDER_EMAIL"]
ses = boto3.client("ses")

# -------------------- HTML EMAIL TEMPLATES --------------------
INVITE_TEMPLATE = """
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
    h1 { font-size: 22px; color: #222831; }
    p { font-size: 15px; line-height: 1.6; }
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
    .username { font-weight: bold; color: #2563eb; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Hi {{FULL_NAME}},<h2>
    <p>You’ve been invited to join <strong>Timesheets Project</strong>.</p>
    <p>Click below to set your password and activate your account.</p>
    <p class="footer">Username: <span class="username">{{USER_EMAIL}}</span></p>
    <a class="button" href="{{SETUP_LINK}}">Set your password</a>
  </div>
</body>
</html>
"""

RESET_TEMPLATE = """
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
    h1 { font-size: 22px; color: #222831; }
    p { font-size: 15px; line-height: 1.6; }
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
    .username { font-weight: bold; color: #2563eb; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Hi {{FULL_NAME}},<h2>
    <p>Click below to reset your password.</p>
    <p class="footer">Username: <span class="username">{{USER_EMAIL}}</span></p>
    <a class="button" href="{{SETUP_LINK}}">Set your password</a>
  </div>
</body>
</html>
"""

# -------------------- PLAIN TEXT FALLBACKS --------------------
INVITE_TEXT_TEMPLATE = """Hi {full_name},

You’ve been invited to join Timesheets Project.

Username: {user_email}
Set your password here: {setup_link}
"""

RESET_TEXT_TEMPLATE = """Hi {full_name},

Click the link below to reset your Timesheets password.

Username: {user_email}
Reset link: {setup_link}
"""

# -------------------- RENDERERS --------------------
def render_email(template: str, text_template: str, setup_link: str, user_email: str, full_name: str = "there"):
    html = (
        template
        .replace("{{SETUP_LINK}}", setup_link)
        .replace("{{USER_EMAIL}}", user_email)
        .replace("{{FULL_NAME}}", full_name)
    )
    text = text_template.format(full_name=full_name, user_email=user_email, setup_link=setup_link)
    return html, text

def render_invitation_email(setup_link: str, user_email: str, full_name: str = "there"):
    return render_email(INVITE_TEMPLATE, INVITE_TEXT_TEMPLATE, setup_link, user_email, full_name)

def render_reset_password_email(setup_link: str, user_email: str, full_name: str = "there"):
    return render_email(RESET_TEMPLATE, RESET_TEXT_TEMPLATE, setup_link, user_email, full_name)

# -------------------- SES SENDER --------------------
def send_email(recipient_email: str, subject: str, html_content: str, text_content: str):
    try:
        ses.send_email(
            Source=f"Timesheets <{SES_SENDER_EMAIL}>",
            Destination={"ToAddresses": [recipient_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Html": {"Data": html_content},
                    "Text": {"Data": text_content}
                }
            }
        )
    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to send email: {str(e)}")
