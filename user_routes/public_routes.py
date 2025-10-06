# -------------------- IMPORTS --------------------
import os
import re
import json
from datetime import datetime, timedelta

# ——— Third-Party Libraries ———
import bcrypt
import boto3
import jwt
from boto3.dynamodb.conditions import Attr, Key
from http.cookies import SimpleCookie

# ——— Custom Utilities ———
from email_utils import render_invitation_email, send_email
from token_utils import *

# -------------------- CONFIGURATION --------------------
ACCESS_TOKEN_EXPIRY        = 1440    # minutes → 24 hours
REFRESH_TOKEN_EXPIRY       = 43200   # minutes → 30 days
RESET_LIMIT_COUNT          = 3
RESET_LIMIT_WINDOW_MINUTES = 60



# -------------------- SETUP PASSWORD FROM TOKEN --------------------
def handle_set_password_from_token(request_body):
    # ——— Validate Inputs ———
    token = request_body.get("token")
    new_password = request_body.get("newPassword")

    if not token or not new_password:
        return {"error": "Token and new password are required"}

    # ——— Decode & Validate Token ———
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("purpose") != "setup":
            return {"error": "Invalid token purpose"}
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

    user_id = payload["sub"]

    # ——— Fetch User Record ———
    user = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if not user:
        return {"error": "User not found"}

    # ——— Hash & Update Password in USERS_TABLE ———
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode("utf-8")
    USERS_TABLE.update_item(
        Key={"userID": user_id},
        UpdateExpression="SET passwordHash = :pw, #st = :st, loginEnabled = :le",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":pw": hashed_password, ":st": "Active", ":le": True},
    )

    # ——— Update EMPLOYEES_TABLE only if approach == "old" ———
    if user.get("approach") == "old":
        EMPLOYEES_TABLE.update_item(
            Key={"employeeID": user_id},
            UpdateExpression="SET loginEnabled = :le",
            ExpressionAttributeValues={":le": True},
        )

    # ——— Email sending rules ———
    recipient_email = user.get("officialEmail", "")
    approach = user.get("approach")

    if approach in ("old", "new_email") and recipient_email:
        username = user.get("username", "")
        subject = "Your Timesheets Account is Ready"
        frontend_url = os.environ.get("FRONTEND_URL", "#")

        # ——— HTML Email Body ———
        html_body = f"""
        <html>
          <head>
            <style>
              body {{
                margin: 0;
                padding: 0;
                font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                background-color: #f9fafb;
              }}
              .container {{
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                padding: 32px;
                color: #374151;
              }}
              h2 {{
                margin-top: 0;
                font-size: 20px;
                color: #1f2937;
              }}
              p {{
                font-size: 15px;
                margin: 16px 0;
              }}
              .info {{
                font-size: 14px;
                color: #6b7280;
                margin: 12px 0;
              }}
              .button {{
                display: inline-block;
                margin-top: 24px;
                padding: 12px 20px;
                background-color: #2563eb;
                color: #ffffff;
                text-decoration: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
              }}
            </style>
          </head>
          <body>
            <div class="container">
              <h2>Hi {username},</h2>
              <p>Your password has been successfully set.</p>
              <p>You can now log in to your Timesheets account using your credentials:</p>
              <p class="info">
                Username: <strong>{username}</strong><br/>
                Email: <strong>{recipient_email}</strong>
              </p>
              <a href="{frontend_url}" target="_blank" class="button">Log in to Timesheets</a>
            </div>
          </body>
        </html>
        """

        # ——— Plain-Text Fallback ———
        text_body = f"""
        Hi {username},

        Your password has been successfully set.
        You can now log in to your Timesheets account using your credentials.

        Username: {username}
        Email: {recipient_email}

        Log in here: {frontend_url}
        """

        try:
            send_email(
                recipient=recipient_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )
        except Exception as e:
            return {"error": f"Failed to send confirmation email: {str(e)}"}

    # ——— Final Response ———
    return {"message": "Password set successfully"}








# -------------------- SIGN IN --------------------
def handle_signin(request_body):
    # ——— Input Validation ———
    login_identifier = request_body.get("identifier", "").lower()
    login_password   = request_body.get("password")

    if not login_identifier or not login_password:
        validation_errors = {}
        if not login_identifier:
            validation_errors["identifier"] = "Username or email is required"
        if not login_password:
            validation_errors["password"] = "Password is required"
        return build_response(error="Validation error", data=validation_errors, status=400)

    # ——— Authenticate Credentials ———
    user_record = find_user_by_email_or_username(login_identifier)
    
    if user_record is None:
        return build_response(
            error="Invalid username/email or password",
            data={"identifier": "Invalid username/email or password"},
            status=401
        )
    if not isinstance(user_record, dict):
        return build_response(
            error="Server error",
            data={"identifier": "Unexpected user data format"},
            status=500
        )

    # Check if passwordHash exists
    if "passwordHash" not in user_record or not user_record["passwordHash"]:
        return build_response(
            error="Invalid username/email or password",
            data={"identifier": "Invalid username/email or password"},
            status=401
        )

    # Verify password
    try:
        if not bcrypt.checkpw(login_password.encode(), user_record["passwordHash"].encode()):
            return build_response(
                error="Invalid username/email or password",
                data={"identifier": "Invalid username/email or password"},
                status=401
            )
    except Exception:
        return build_response(
            error="Authentication error",
            data={"identifier": "Error verifying password"},
            status=500
        )

    # --- Extract core fields ---
    user_id        = user_record["userID"]
    official_email = user_record.get("officialEmail", "")
    approach       = user_record.get("approach", "old")   # default = old for backward compat

    # --- Roles field supports multiple roles
    assigned_roles = user_record.get("roles", [])
    if isinstance(assigned_roles, str):
        assigned_roles = [assigned_roles]

    print("Assigned->>>>", assigned_roles)

    # ——— Access Control Based on Approach ———
    first_name, last_name = "", ""

    if approach == "old":
        try:
            employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": user_id}).get("Item", {}) or {}
            if not employee_record or not employee_record.get("loginEnabled", False):
                return build_response(
                    error="Access denied",
                    data={"identifier": "Login not allowed for this user"},
                    status=403
                )
            first_name = employee_record.get("firstName", "")
            last_name  = employee_record.get("lastName", "")
        except Exception:
            return build_response(
                error="Server error",
                data={"identifier": "Error fetching employee record"},
                status=500
            )

    else:  # new_email or new_password
        if not user_record.get("loginEnabled", False):
            return build_response(
                error="Access denied",
                data={"identifier": "Login not allowed for this user"},
                status=403
            )
        first_name = user_record.get("firstName", "")
        last_name  = user_record.get("lastName", "")

    full_name = f"{first_name} {last_name}".strip()

    # ——— Retrieve Last Login ———
    last_login_timestamp = user_record.get("lastLogin")

    # ——— Generate Tokens ———
    try:
        access_token  = generate_token(user_id, official_email, assigned_roles, ACCESS_TOKEN_EXPIRY)
        refresh_token = generate_token(user_id, official_email, assigned_roles, REFRESH_TOKEN_EXPIRY)
    except Exception:
        return build_response(
            error="Server error",
            data={"identifier": "Error generating tokens"},
            status=500
        )

    # ——— Update Refresh Token & Last Login ———
    try:
        current_login_time = datetime.utcnow().isoformat() + "Z"
        USERS_TABLE.update_item(
            Key={"userID": user_id},
            UpdateExpression="SET refreshToken = :refresh, lastLogin = :last",
            ExpressionAttributeValues={
                ":refresh": refresh_token,
                ":last": current_login_time
            }
        )
    except Exception:
        return build_response(
            error="Server error",
            data={"identifier": "Error updating user record"},
            status=500
        )

    # ——— Prepare Secure Refresh-Token Cookie ———
    refresh_token_cookie = (
        f"refreshToken={refresh_token}; HttpOnly; Secure; Path=/; "
        f"SameSite=None; Max-Age={REFRESH_TOKEN_EXPIRY * 60}"
    )

    # ——— Get Modules User Can View ———
    try:
        modules_user_can_view = get_viewable_modules(user_id, assigned_roles)
        print("Modules->>>>", modules_user_can_view)
    except Exception:
        modules_user_can_view = []

    # ——— Load Profile Information ———
    profile_picture_url = user_record.get("profilePictureURL", "")

    # ——— Return Authenticated Response ———
    return build_response(
        data={
            "fullName": full_name,
            "userID": user_id,
            "email": official_email,
            "roles": assigned_roles,
            "moduleAccess": modules_user_can_view,  
            "profilePictureURL": profile_picture_url,
            "accessToken": access_token,
            "lastLogin": last_login_timestamp
        },
        cookies=refresh_token_cookie
    )




# -------------------- REFRESH TOKEN --------------------
def handle_refresh_token(event):
    # ——— Extract Refresh Token from Cookie ———
    refresh_token = get_refresh_token_from_cookie(event)
    if not refresh_token:
        return build_response(
            error="Validation error",
            data={"refreshToken": "Missing from cookie"},
            status=401
        )

    # ——— Decode Refresh Token ———
    try:
        decoded_token = jwt.decode(refresh_token, JWT_SECRET, algorithms=["HS256"])
        user_id = decoded_token["sub"]
    except jwt.ExpiredSignatureError:
        return build_response(error="Token has expired", status=401)
    except jwt.InvalidTokenError:
        return build_response(error="Invalid token", status=401)

    # ——— Fetch User Record ———
    user_record = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if not user_record:
        return build_response(error="User not found", status=404)

    user_email = user_record["officialEmail"]
    user_role = user_record["role"]

    # ——— Generate New Tokens ———
    new_refresh_token = generate_token(user_id, user_email, user_role, REFRESH_TOKEN_EXPIRY)
    new_access_token = generate_token(user_id, user_email, user_role, ACCESS_TOKEN_EXPIRY)

    # ——— Update User Record with New Refresh Token ———
    USERS_TABLE.update_item(
        Key={"userID": user_id},
        UpdateExpression="SET refreshToken = :refresh",
        ExpressionAttributeValues={":refresh": new_refresh_token}
    )

    # ——— Prepare Refresh Token Cookie ———
    refresh_cookie = (
        f"refreshToken={new_refresh_token}; HttpOnly; Secure; Path=/; "
        f"SameSite=None; Max-Age={REFRESH_TOKEN_EXPIRY * 60}"
    )

    # ——— Return New Access Token ———
    return build_response(
        data={"accessToken": new_access_token},
        cookies=refresh_cookie
    )


# -------------------- FORGOT PASSWORD REQUEST --------------------
def handle_forgot_password_request(request_body):
    # ——— Validate Input ———
    identifier = request_body.get("identifier")
    if not identifier:
        return {"error": "Validation error", "message": "Identifier (username or email) is required"}

    # ——— Lookup User ———
    user_record = find_user_by_email_or_username(identifier)
    if not user_record:
        return {"error": "User not found"}

    user_id = user_record["userID"]
    user_email = user_record.get("officialEmail", "")

    # ——— Guard: Ensure Email Exists ———
    if not user_email:
        return {
            "error": "No email associated with this account",
            "message": "This user cannot receive password reset emails."
        }

    # ——— Rate Limit: Reset Email History ———
    current_time = datetime.utcnow()
    previous_reset_history = user_record.get("resetEmailHistory", [])

    valid_reset_history = [
        timestamp for timestamp in previous_reset_history
        if isinstance(timestamp, str)
        and current_time - datetime.fromisoformat(timestamp) < timedelta(minutes=RESET_LIMIT_WINDOW_MINUTES)
    ]

    if len(valid_reset_history) >= RESET_LIMIT_COUNT:
        return {
            "error": "Too many requests",
            "message": f"You can only request {RESET_LIMIT_COUNT} reset emails within {RESET_LIMIT_WINDOW_MINUTES} minutes."
        }

    # ——— Generate Reset Token and Link ———
    reset_token = generate_setup_or_reset_token(user_id, user_email, "reset", 120)
    reset_link = f"{os.environ.get('FRONTEND_URL')}/set-password?token={reset_token}"

    # ——— Send Reset Email ———
    try:
        subject = "Reset Your Timesheets Password"
        html_body = render_invitation_email(
            setup_link=reset_link,
            user_email=user_email,
            is_password_reset=True
        )
        send_email(user_email, subject, html_body)
    except Exception as email_error:
        return {"error": f"Failed to send reset email: {str(email_error)}"}

    # ——— Update Reset Email History ———
    updated_reset_history = valid_reset_history + [current_time.isoformat()]
    USERS_TABLE.update_item(
        Key={"userID": user_id},
        UpdateExpression="SET resetEmailHistory = :history",
        ExpressionAttributeValues={":history": updated_reset_history}
    )

    # ——— Success Response ———
    return {
        "message": "Password reset link has been sent to your email address.",
        "resetToken": reset_token
    }






# -------------------- RESET PASSWORD VIA TOKEN --------------------
def handle_forgot_password_reset(request_body):
    # ——— Validate Input ———
    token = request_body.get("token")
    new_password = request_body.get("newPassword")

    if not token or not new_password:
        return {"error": "Validation error", "message": "Token and new password are required"}

    # ——— Decode and Validate Token ———
    try:
        token_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if token_payload.get("purpose") != "reset":
            return {"error": "Invalid token purpose"}
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

    # ——— Fetch User Record ———
    user_id = token_payload["sub"]
    user_record = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if not user_record:
        return {"error": "User not found"}

    # ——— Hash and Update Password ———
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode("utf-8")
    USERS_TABLE.update_item(
        Key={"userID": user_id},
        UpdateExpression="SET passwordHash = :password",
        ExpressionAttributeValues={":password": hashed_password}
    )

    # ——— Success Response ———
    return {"message": "Your password has been reset successfully"}
