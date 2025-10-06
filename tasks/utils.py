import json
import os
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
from policy_engine import evaluate, AccessRequest

# -------------------- AWS DynamoDB Resources --------------------
dynamodb = boto3.resource("dynamodb")

TASKS_TABLE           = dynamodb.Table(os.environ.get("TASKS_TABLE"))
ROLE_PRIVILEGES_TABLE = dynamodb.Table(os.environ.get("ROLE_PRIVILEGES_TABLE"))
SEQUENCES_TABLE       = dynamodb.Table(os.environ.get("SEQUENCES_TABLE"))
EMPLOYEE_TABLE        = dynamodb.Table(os.environ.get("EMPLOYEE_TABLE"))
ASSIGNMENTS_TABLE     = dynamodb.Table(os.environ.get("PROJECT_ASSIGNMENTS_TABLE"))
PROJECTS_TABLE        = dynamodb.Table(os.environ.get("PROJECTS_TABLE"))


# ——— Dynamic CORS Headers ———
def get_cors_headers(event):

    origin = event.get("headers", {}).get("origin", "")

    allowed_origins = [
        "http://localhost:3000",
        "http://192.168.0.224:3000",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev"
    ]

    cors_origin = origin if origin in allowed_origins else "null"

    return {
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true"
    }


# ——— Build HTTP Response ———
def build_response(data=None, *, status=200, error=None, event=None):

    return {
        "statusCode": status if not error else (status or 400),
        "headers": get_cors_headers(event or {}),
        "body": json.dumps({"error": error} if error else (data or {})),
    }


# ——— Generate Unique Display ID ———
def generate_unique_display_id(prefix: str) -> str:

    try:
        response = SEQUENCES_TABLE.update_item(
            Key={"prefix": prefix.upper()},
            UpdateExpression="SET lastValue = if_not_exists(lastValue, :start) + :inc, updatedAt = :now",
            ExpressionAttributeValues={
                ":start": 0,
                ":inc": 1,
                ":now": datetime.utcnow().isoformat()
            },
            ReturnValues="UPDATED_NEW"
        )

        # Increment and return formatted ID
        current_number = int(response["Attributes"]["lastValue"])
        return f"{prefix.upper()}-{str(current_number).zfill(5)}"

    except ClientError as e:
        raise Exception(f"Failed to generate ID for prefix '{prefix}': {e.response['Error']['Message']}")


# ——— Format Date ———
def format_date_mmddyyyy(date_str: str) -> str:

    try:
        dt = datetime.fromisoformat(date_str)
        return dt.strftime("%m-%d-%Y")
    except Exception:
        return date_str


# ——— Get Full Name ———
def get_user_full_name(user_id: str) -> str:

    try:
        user = EMPLOYEE_TABLE.get_item(Key={"employeeID": user_id}).get("Item", {})
        full_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip()
        return full_name if full_name else "Unknown"
    except Exception:
        return "Unknown"


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

    # Run evaluation
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

    # Return 403 if explicitly denied
    if decision.get("decision") == "DENY":
        reason = decision.get("reason") or "explicit deny"
        return build_response(
            data={"error": f"Not authorized to {resource}.{action} ({reason})"},
            status=403,
            event=event,
        )

    return None
