import json
import os
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from typing import List, Dict, Any, Set
from policy_engine import evaluate, AccessRequest


# -------------------- AWS Resources --------------------
dynamodb_resource = boto3.resource("dynamodb")

ASSIGNMENTS_TABLE = dynamodb_resource.Table(os.environ["PROJECT_ASSIGNMENTS_TABLE"])
PROJECTS_TABLE = dynamodb_resource.Table(os.environ["PROJECTS_TABLE"])
USERS_TABLE = dynamodb_resource.Table(os.environ["USERS_TABLE"])
ROLE_PRIVILEGES_TABLE = dynamodb_resource.Table(os.environ["ROLE_PRIVILEGES_TABLE"])
SEQUENCES_TABLE = dynamodb_resource.Table(os.environ["SEQUENCES_TABLE"])
EMPLOYEES_TABLE = dynamodb_resource.Table(os.environ["EMPLOYEES_TABLE"])
CONTACT_TABLE = dynamodb_resource.Table(os.environ["CONTACT_TABLE"])
ROLE_POLICIES_TABLE = dynamodb_resource.Table(os.environ["ROLE_POLICIES_TABLE"])


# ——— CORS Headers Function ———
def get_cors_headers(request_event):

    # Extract headers safely
    request_headers = (request_event.get("headers") or {}) if isinstance(request_event, dict) else {}

    # Try both lowercase and capitalized "Origin"
    request_origin = request_headers.get("origin") or request_headers.get("Origin") or ""

    # Allowed frontend origins
    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://timesheets.test.inferai.ai",
        "http://192.168.0.224:3000",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev"
    ]

    # Echo origin if valid, else return "null"
    return {
        "Access-Control-Allow-Origin": request_origin if request_origin in allowed_origins else "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }



# ——— Response Builder Function ———
def build_response(event, data=None, *, status=200, error=None):

    # Use error response if provided
    return {
        "statusCode": status if not error else (status or 400),
        "headers": get_cors_headers(event or {}),
        "body": json.dumps({"error": error} if error else (data or {})),
    }


# ——— Display ID Generator Function ———
def generate_unique_display_id(prefix):

    # Ensure prefix is valid
    upper_prefix = (prefix or "").upper()
    if not upper_prefix:
        raise Exception("Failed to generate ID: missing prefix")

    try:
        # Atomically increment counter in SEQUENCES_TABLE
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

        # Extract current sequence number
        current_value = int(update_result["Attributes"]["lastValue"])
        return f"{upper_prefix}-{current_value:05d}"

    except ClientError as client_error:
        # Extract detailed error message
        message = client_error.response.get("Error", {}).get("Message", "Unknown error")
        raise Exception(f"Failed to generate ID for {upper_prefix}: {message}")

    except Exception:
        # Fallback for unexpected errors
        raise Exception(f"Failed to generate ID for {upper_prefix}: unexpected error")


# ——— Date Formatter Function ———
def format_date_to_mm_dd_yyyy(iso_datetime_string):

    try:
        # Parse ISO string to datetime and reformat
        parsed_datetime = datetime.fromisoformat(iso_datetime_string)
        return parsed_datetime.strftime("%m-%d-%Y")

    except Exception:
        # Return original input if parsing fails
        return iso_datetime_string


# ——— Decision Wrapper Function ———
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

    # Build target context
    target_context = {"module": resource}
    if record_type:
        target_context["recordType"] = record_type
    if record_id:
        target_context["recordId"] = record_id
    if extra_context:
        target_context.update({key: value for key, value in extra_context.items() if key != "createdBy"})

    # Run policy evaluation
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

    # Deny response if explicitly denied
    if decision.get("decision") == "DENY":
        reason = decision.get("reason") or "explicit deny"
        return build_response(
            event,
            status=403,
            data={"error": f"Not authorized to {resource}.{action} ({reason})"},
        )

    return None
