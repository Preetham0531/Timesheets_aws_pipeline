import os
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

# ——— DynamoDB Table References ———

dynamodb = boto3.resource("dynamodb")
CONTACTS_TABLE = dynamodb.Table(os.environ["contact_table"])
CLIENTS_TABLE = dynamodb.Table(os.environ["CLIENTS_TABLE"])
USERS_TABLE = dynamodb.Table(os.environ["USERS_TABLE"])
ROLE_PRIVILEGES_TABLE = dynamodb.Table(os.environ["ROLE_PRIVILEGES_TABLE"])
EMPLOYEES_TABLE = dynamodb.Table(os.environ["EMPLOYEES_TABLE"])
SEQUENCES_TABLE = dynamodb.Table(os.environ["SEQUENCES_TABLE"])
PROJECTS_TABLE = dynamodb.Table(os.environ["PROJECTS_TABLE"])
ASSIGNMENTS_TABLE = dynamodb.Table(os.environ["ASSIGNMENTS_TABLE"])


# ——— CORS ———

ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://192.168.0.224:3000",
    "https://test.d33utl6pegyzdw.amplifyapp.com",
    "https://test-copy.dqa87374qqtdj.amplifyapp.com",
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

def get_cors_headers(event):
    """
    Build CORS headers for the current request.
    If the Origin header is in the allowed list, echo it; otherwise set to 'null'.
    """
    headers = event.get("headers", {}) or {}
    origin = headers.get("origin") or headers.get("Origin") or ""
    return {
        "Access-Control-Allow-Origin": origin if origin in ALLOWED_ORIGINS else "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }


# ——— Response ———

def build_response(data=None, *, status=200, error=None, event=None, headers=None):
    """
    Build a standard API response with CORS headers and JSON body.
    - If 'headers' is not provided, CORS headers are derived from 'event'.
    - When 'error' is provided, returns {"error": "<message>"} and normalizes status
      using a fixed mapping; otherwise uses the provided 'status'.
    """
    cors_headers = headers if headers is not None else get_cors_headers(event or {})

    if error:
        body = {"error": error}
        status = {
            "Validation error": 400,
            "Invalid credentials": 401,
            "Unauthorized": 401,
            "Forbidden": 403,
            "Invalid or expired token": 400,
        }.get(error, status if status != 200 else 400)
    else:
        body = data or {}

    return {
        "statusCode": status,
        "headers": cors_headers,
        "body": json.dumps(body, default=str),
    }


# ——— Authorization ———

def authorize_action(user_id, role, required_privilege, event=None):
    """
    Validate that the user possesses the required privilege.
    Returns None when authorized; otherwise returns a 403 (missing privilege)
    or 500 (lookup failure). Errors are returned in the main 'error' string.
    """
    try:
        record = ROLE_PRIVILEGES_TABLE.get_item(Key={"userID": user_id}).get("Item") or {}
        privileges = record.get("privileges", [])
        if required_privilege in privileges:
            return None

        return build_response(
            error=f"Forbidden: missing privilege",
            status=403,
            event=event,
        )
    except Exception:
        return build_response(
            error="Forbidden: privilege lookup failed",
            status=500,
            event=event,
        )



# ——— Utilities ———

def format_date(iso_datetime_string):
    """
    Convert an ISO 8601 datetime string to MM-DD-YYYY.
    Returns the original string on parse errors.
    """
    try:
        return datetime.fromisoformat(iso_datetime_string).strftime("%m-%d-%Y")
    except Exception:
        return iso_datetime_string


def get_user_name(user_id):
    """
    Resolve a display name for a user ID.
    Uses firstName + lastName when available, otherwise falls back to user_id.
    Returns 'Unknown' when input is empty.
    """
    if not user_id:
        return "Unknown"
    try:
        user = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
        if not user:
            return user_id
        name = f"{user.get('firstName','')} {user.get('lastName','')}".strip()
        return name or user_id
    except Exception:
        return "Unknown"
def get_username(user_id: str) -> str:
    """
    Get username from USERS_TABLE
    
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
        
    except Exception:
        return str(user_id)

def get_client_name(client_id):
    """
    Resolve companyName for a client ID. Falls back to the ID when not found.
    Returns 'Unknown' when input is empty.
    """
    if not client_id:
        return "Unknown"
    try:
        client = CLIENTS_TABLE.get_item(Key={"clientID": client_id}).get("Item")
        return client.get("companyName", client_id) if client else client_id
    except Exception:
        return client_id


def get_contact_name(contact_id):
    """
    Resolve a contact's display name from firstName + lastName, or contactName.
    Falls back to the ID when not found. Returns 'Unknown' when input is empty.
    """
    if not contact_id:
        return "Unknown"
    try:
        contact = CONTACTS_TABLE.get_item(Key={"contactID": contact_id}).get("Item")
        if not contact:
            return contact_id
        name = f"{contact.get('firstName','')} {contact.get('lastName','')}".strip()
        return name or contact.get("contactName", contact_id)
    except Exception:
        return contact_id


def enrich_contact_metadata(contact_item):
    """
    Enrich a contact item with display names and formatted timestamps:
      - createdByName, clientName
      - createdAt, updatedAt formatted as MM-DD-YYYY (when parseable)
    Mutates the provided dict in place.
    """
    contact_item["createdByName"] = get_user_name(contact_item.get("createdBy"))
    contact_item["clientName"] = get_client_name(contact_item.get("clientID"))
    contact_item["createdAt"] = format_date(contact_item.get("createdAt", ""))
    contact_item["updatedAt"] = format_date(contact_item.get("updatedAt", ""))


def generate_unique_display_id(prefix: str) -> str:
    """
    Generate a unique display ID using SEQUENCES_TABLE.
    Returns '<PREFIX>-00001' style IDs, incrementing atomically.
    Raises an Exception with a concise message on failure.
    """
    upper_prefix = (prefix or "").upper()
    if not upper_prefix:
        raise Exception("Failed to generate ID: missing prefix")
    try:
        result = SEQUENCES_TABLE.update_item(
            Key={"prefix": upper_prefix},
            UpdateExpression="SET lastValue = if_not_exists(lastValue, :start) + :inc, updatedAt = :now",
            ExpressionAttributeValues={
                ":start": 0,
                ":inc": 1,
                ":now": datetime.utcnow().isoformat(),
            },
            ReturnValues="UPDATED_NEW",
        )
        value = int(result["Attributes"]["lastValue"])
        return f"{upper_prefix}-{str(value).zfill(5)}"
    except ClientError as e:
        message = e.response.get("Error", {}).get("Message", "Unknown error")
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': {message}")
    except Exception:
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': unexpected error")

