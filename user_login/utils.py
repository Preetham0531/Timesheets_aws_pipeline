# -------------------- IMPORTS --------------------
import os
import jwt
import json
import boto3
import time
import uuid
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Set
from policy_engine import evaluate, AccessRequest
from boto3.dynamodb.conditions import Key

import logging

# -------------------- CONFIGURATION --------------------
JWT_SECRET = os.environ["JWT_SECRET"]
S3_BUCKET_NAME = os.environ["S3_BUCKET_NAME"]

# -------------------- DYNAMODB RESOURCES --------------------
dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client('dynamodb')


USERS_TABLE               = dynamodb.Table(os.environ["USERS_TABLE"])
CREDENTIALS_TABLE         = dynamodb.Table(os.environ["CREDENTIALS_TABLE"])
ROLE_PRIVILEGES_TABLE     = dynamodb.Table(os.environ["ROLE_PRIVILEGES_TABLE"])
EMPLOYEES_TABLE           = dynamodb.Table(os.environ["EMPLOYEES_TABLE"])
SEQUENCES_TABLE           = dynamodb.Table(os.environ["SEQUENCES_TABLE"])
CONTACT_TABLE             = dynamodb.Table(os.environ["CONTACTS_TABLE"])
ROLES_TABLE               = dynamodb.Table(os.environ.get("ROLE_POLICIES_TABLE"))
ROLE_BY_NAME_INDEX        = os.environ.get("ROLE_BY_NAME_INDEX")
USER_GRANTS_TABLE         = dynamodb.Table(os.environ.get("USER_GRANTS_TABLE"))

# -------------------- TOKEN GENERATION (SETUP/RESET) --------------------
def generate_setup_or_reset_token(user_id, email, purpose, minutes):
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "email": email,
        "purpose": purpose,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# -------------------- CORS HEADER BUILDER --------------------
def get_cors_headers(event):
    origin = (
        event.get("headers", {}).get("origin")
        or event.get("headers", {}).get("Origin")
        or (event.get("multiValueHeaders", {}).get("origin") or [None])[0]
        or ""
    ).rstrip("/")

    allowed_origins = {
        "http://localhost:3000",
        "http://192.168.0.224:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://test.d2zasimyd0ou3m.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheetdemo.netlify.app",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "https://labs.inferai.ai",
        "https://www.labs.inferai.ai",
        "http://localhost:48752",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
"https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.projects.builder.codes",
    "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.fly.dev"
    }
    cors_origin = origin if origin in allowed_origins else "*"

    return {
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
    }


# -------------------- STANDARD RESPONSE WRAPPER --------------------
def build_response(event=None, data=None, *, status=200, error=None, cookies=None, plain_text=False):
    # ——— Headers ———
    headers = get_cors_headers(event)
    if cookies:
        headers["Set-Cookie"] = cookies

    # ——— Body ———
    if plain_text:
        body = data if isinstance(data, str) else str(data)
    else:
        body = {"error": error} if error else (data or {})
        body = json.dumps(body, default=str)

    # ——— Response ———
    return {"statusCode": status, "headers": headers, "body": body}



def generate_uuid() -> str:
    """Generate a unique UUID v4 string for userID."""
    return str(uuid.uuid4())


# -------------------- UNIQUE ID GENERATOR --------------------
def generate_unique_display_id(prefix: str) -> str:
    prefix = prefix.upper()
    try:
        result = SEQUENCES_TABLE.update_item(
            Key={"prefix": prefix},
            UpdateExpression="SET lastValue = if_not_exists(lastValue, :start) + :step, updatedAt = :timestamp",
            ExpressionAttributeValues={
                ":start": 0,
                ":step": 1,
                ":timestamp": datetime.utcnow().isoformat()
            },
            ReturnValues="UPDATED_NEW"
        )
        sequence_number = int(result["Attributes"]["lastValue"])
        return f"{prefix}-{sequence_number:05d}"
    except ClientError as error:
        raise Exception(
            f"ID generation failed for prefix '{prefix}': {error.response['Error']['Message']}"
        )



def get_user_full_name(user_id):
    """
    Fetch a user's full name.
    - First checks EMPLOYEES_TABLE
    - If not found, checks USERS_TABLE
    - Falls back to "Non-Employee"
    """
    # --- First, try Employees table ---
    emp_item = EMPLOYEES_TABLE.get_item(Key={"employeeID": user_id}).get("Item", {}) or {}
    first = emp_item.get("firstName", "").strip()
    last = emp_item.get("lastName", "").strip()
    if first or last:
        return f"{first} {last}".strip()

    # --- If not found, try Users table ---
    user_item = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item", {}) or {}
    first = user_item.get("firstName", "").strip()
    last = user_item.get("lastName", "").strip()
    if first or last:
        return f"{first} {last}".strip()

    # --- Final fallback ---
    return "Non-Employee"





def nowIso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def validateRoleIdsExist(rids: list[str]) -> list[str]:
    """Check which role IDs exist in ROLES_TABLE by PK rid."""
    valid_rids: set[str] = set()
    for rid in {str(r).strip() for r in (rids or []) if str(r).strip()}:
        resp = ROLES_TABLE.query(KeyConditionExpression=Key("rid").eq(rid), Limit=1)
        items = resp.get("Items", []) or []
        if items:
            valid_rids.add(rid)
    return sorted(valid_rids)




def fetchCurrentRoleAssignments(user_id: str) -> list[dict[str, Any]]:
    """Fetch all role assignment rows (A#ROLE#*) for a given user from USER_GRANTS_TABLE."""
    response = USER_GRANTS_TABLE.query(KeyConditionExpression=Key("userID").eq(user_id))
    items = response.get("Items", []) or []
    return [item for item in items if str(item.get("ovID", "")).startswith("A#ROLE#")]


def putRoleAssignment(user_id: str, rid: str, role_name: str, created_by: str) -> None:
    """
    Create/activate a role assignment for a user.
    Requires both rid and role_name (no guessing).
    """
    current_time = nowIso()
    assignment_id = f"A#ROLE#{role_name}"

    # Upsert into UserGrants
    USER_GRANTS_TABLE.put_item(Item={
        "userID": user_id,
        "ovID": assignment_id,
        "entityType": "UserRole",
        "rid": rid,
        "role": role_name,
        "module": "-",
        "contextType": "-",
        "contextId": "-",
        "Status": "active",
        "status": "active",
        "createdAt": current_time,
        "createdBy": created_by,
        "updatedAt": current_time,
        "note": f"Role assignment for {role_name}",
    })

    # Increment rolecount in roles_t
    ROLES_TABLE.update_item(
        Key={"rid": rid, "role": role_name},
        UpdateExpression="SET rolecount = if_not_exists(rolecount, :zero) + :inc",
        ExpressionAttributeValues={":inc": 1, ":zero": 0}
    )





def deactivateRoleAssignment(user_id: str, rid: str, role_name: str) -> None:
    """
    Deactivate a role assignment and decrement rolecount.
    Requires both rid and role_name (no guessing).
    """
    assignment_id = f"A#ROLE#{role_name}"

    # Mark inactive in UserGrants
    USER_GRANTS_TABLE.update_item(
        Key={"userID": user_id, "ovID": assignment_id},
        UpdateExpression="SET #s = :inactive, Status = :inactive, updatedAt = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":inactive": "inactive", ":now": nowIso()},
    )

    # Decrement rolecount safely
    ROLES_TABLE.update_item(
        Key={"rid": rid, "role": role_name},
        UpdateExpression="SET rolecount = if_not_exists(rolecount, :zero) - :dec",
        ExpressionAttributeValues={":dec": 1, ":zero": 0},
        ConditionExpression="attribute_exists(rolecount) AND rolecount > :zero"
    )





def sanitize_user_record(user_record: dict) -> dict:
    """
    Remove sensitive fields from user record before returning to client.
    """
    if not user_record:
        return {}

    allowed_fields = {
        "userID",
        "employeeID",
        "username",
        "displayID",
        "officialEmail",
        "roles",
        "status",
        "loginEnabled",
        "lastLogin",
        "createdAt",
        "createdBy",
        "updatedAt",
        "updatedBy",
        "profilePictureURL",
    }

    return {k: v for k, v in user_record.items() if k in allowed_fields}


def get_primary_role_id(role_names: list[str]) -> str | None:
    """
    Fetch the roleID (rid) for the first valid role in the list.
    Assumes roles array usually has one main role.
    """
    if not role_names:
        return None

    role_name = role_names[0]  # take first role only
    resp = ROLES_TABLE.query(
        IndexName=os.getenv("ROLE_BY_NAME_INDEX", "role-rid-index"),
        KeyConditionExpression=Key("role").eq(role_name),
        Limit=1,
    )
    item = (resp.get("Items") or [None])[0]
    return item.get("rid") if item else None

# ========= DECISION WRAPPER =========
def decision_or_deny(
    event,
    user_id: str,
    resource: str,
    action: str,
    *,
    record_id: str | None = None,
    record_type: str | None = None,
    extra_context: dict | None = None,
    resource_object: dict | None = None,
):
    """Evaluate access decision and return a 403 response if denied."""

    target_context = {"module": resource}
    if record_type:
        target_context["recordType"] = record_type
    if record_id:
        target_context["recordId"] = record_id
    if extra_context:
        target_context.update({key: value for key, value in extra_context.items() if key != "createdBy"})

    decision = evaluate(
        AccessRequest(
            user={"id": str(user_id)},
            resourceType=resource,
            action=action,
            targetCtx=target_context,
            resourceId=record_id,
            resource=resource_object,
        )
    )
    print(f"Decision:->>>>> {decision}")
    if decision.get("decision") == "DENY":
        reason = decision.get("reason") or "explicit deny"
        return build_response(
            event,
            status=403,
            data={"error": f"Not authorized to {resource}.{action} ({reason})"},
        )

    return None

