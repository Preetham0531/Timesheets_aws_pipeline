import os
import json
import boto3
import logging
from datetime import datetime
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from typing import Any, Dict, List, Optional, Tuple, Iterable, Callable

logger = logging.getLogger("utils")

# ——— DynamoDB Table References ———

dynamodb = boto3.resource("dynamodb")
CLIENTS_TABLE = dynamodb.Table(os.environ["CLIENTS_TABLE"])
ROLE_PRIVILEGES_TABLE = dynamodb.Table(os.environ["ROLE_PRIVILEGES_TABLE"])
USERS_TABLE = dynamodb.Table(os.environ["USERS_TABLE"])
SEQUENCES_TABLE = dynamodb.Table(os.environ["SEQUENCES_TABLE"])
PROJECTS_TABLE = dynamodb.Table(os.environ["PROJECTS_TABLE"])
CONTACTS_TABLE = dynamodb.Table(os.environ["CONTACTS_TABLE"])
ASSIGNMENTS_TABLE = dynamodb.Table(os.environ["ASSIGNMENTS_TABLE"])


# ——— CORS Headers ———

def get_cors_headers(event):
    """
    Build CORS headers for the current request.
    Allows a fixed set of origins; defaults to 'null' when origin is not allowed.
    """
    origin = (
        event.get("headers", {}).get("origin")
        or event.get("headers", {}).get("Origin")
        or ""
    ).rstrip("/")

    allowed_origins = {
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "http://192.168.0.224:3000",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "https://labs.inferai.ai",
        "https://www.labs.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.projects.builder.codes",
    "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.fly.dev"
    }

    cors_origin = origin if origin in allowed_origins else "null"
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,GET,POST,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
    }


# ——— API Response Builder ———

def build_response(event=None, data=None, *, status=200, error=None):
    """
    Build a standard API response with CORS headers and JSON body.
    - If error is provided, returns {"error": "<message>"} and auto-normalizes status when status was 200.
    - Data is returned as given if error is not provided.
    - CORS headers are derived from the event.
    """
    headers = get_cors_headers(event or {})

    if error:
        body = {"error": error}
        if status == 200:
            status = 400 if error == "Validation error" else 403 if error == "Forbidden" else 401
    else:
        body = data or {}

    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body, default=str),
    }

def get_username(user_id: str) -> str:
    """
    Simple function to get username from USERS_TABLE
    
    Args:
        user_id (str): The userID to lookup
        
    Returns:
        str: Username or fallback
    """
    if not user_id or not USERS_TABLE:
        return "unknown"
    
    try:
        response = USERS_TABLE.get_item(Key={"userID": user_id})
        user = response.get("Item")
        
        if user and user.get("username"):
            return user["username"]
        
        # Fallback to user_id
        return str(user_id)
        
    except Exception as e:
        logger.warning(f"Error getting username for {user_id}: {e}")
        return str(user_id)

# ——— Helpers ———

def client_exists(client_name, primary_email):
    """
    Check if a client already exists by name or primary email.
    Returns a tuple: (name_exists: bool, email_exists: bool).
    Raises a generic exception message suitable for API error handling on failure.
    """
    try:
        scan_result = CLIENTS_TABLE.scan(
            FilterExpression=Attr("clientName").eq(client_name) | Attr("primaryEmail").eq(primary_email)
        )
        items = scan_result.get("Items", [])
        name_exists = any(item.get("clientName") == client_name for item in items)
        email_exists = any(item.get("primaryEmail") == primary_email for item in items)
        return name_exists, email_exists
    except Exception:
        # Keep error message generic to avoid leaking internals
        raise Exception("Error checking client existence")


def format_date(iso_datetime_string):
    """
    Format an ISO 8601 datetime string to MM-DD-YYYY.
    Returns the original input when parsing fails or input is not a string.
    """
    try:
        return datetime.fromisoformat(iso_datetime_string).strftime("%m-%d-%Y")
    except Exception:
        return iso_datetime_string


def authorize_action(user_id, role, action_code=None, role_privileges_table=None, privilege=None, table=None):
    """
    Check if user has required privilege (code-based only).
    Returns None if authorized, or build_response(...) with 403 if not.
    """
    code = action_code or privilege
    table_ref = role_privileges_table or table

    if not (user_id and role and code and table_ref):
        return build_response(error="Forbidden", status=403)

    try:
        record = table_ref.get_item(Key={"userID": user_id}).get("Item")
    except Exception:
        return build_response(error="Forbidden", status=403)

    if not record or code not in (record.get("privileges") or []):
        return build_response(error=f"Forbidden: missing privilege '{code}'", status=403)

    return None



def get_user_name(user_id):
    """
    Resolve a user-friendly name for a given user ID.
    Returns:
      - 'username' from USERS_TABLE when available,
      - the raw user_id when record is absent,
      - 'Unknown' on errors or missing ID.
    """
    if not user_id:
        return "Unknown"
    try:
        user_record = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
        if not user_record:
            return user_id
        return user_record.get("username", user_id)
    except Exception:
        return "Unknown"


def generate_unique_display_id(prefix: str) -> str:
    """
    Generate a unique display ID for the given prefix using a sequence table.
    Increments the counter and returns '<PREFIX>-00001' format with zero padding.
    Raises an Exception with a concise message on failure.
    """
    upper_prefix = (prefix or "").upper()
    if not upper_prefix:
        raise Exception("Failed to generate ID: missing prefix")

    try:
        update_result = SEQUENCES_TABLE.update_item(
            Key={"prefix": upper_prefix},
            UpdateExpression="SET lastValue = if_not_exists(lastValue, :start) + :inc, updatedAt = :now",
            ExpressionAttributeValues={
                ":start": 0,
                ":inc": 1,
                ":now": datetime.utcnow().isoformat(),
            },
            ReturnValues="UPDATED_NEW",
        )
        current_value = int(update_result["Attributes"]["lastValue"])
        return f"{upper_prefix}-{str(current_value).zfill(5)}"
    except ClientError as e:
        message = e.response.get("Error", {}).get("Message", "Unknown error")
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': {message}")
    except Exception:
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': unexpected error")


def get_contact_name(contact_id):
    """
    Resolve a contact's display name from CONTACTS_TABLE.
    Returns:
      - 'firstName lastName' when available,
      - 'contactName' fallback,
      - the contact_id itself when not found,
      - contact_id on errors.
    """
    if not contact_id:
        return ""
    try:
        contact_record = CONTACTS_TABLE.get_item(Key={"contactID": contact_id}).get("Item")
        if not contact_record:
            return contact_id
        first = contact_record.get("firstName", "") or ""
        last = contact_record.get("lastName", "") or ""
        full_name = f"{first} {last}".strip()
        return full_name or contact_record.get("contactName", contact_id)
    except Exception:
        return contact_id
