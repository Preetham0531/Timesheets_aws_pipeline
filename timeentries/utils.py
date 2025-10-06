import os
import json
import base64
import mimetypes
import re
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timedelta, date
from policy_engine import evaluate, AccessRequest
import boto3
from boto3.dynamodb.conditions import Attr, Key, Or
from botocore.exceptions import ClientError
from policy_engine import *



# ----------------------- AWS Clients & Resources -----------------------
dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")
s3_client = boto3.client("s3")
SES = boto3.client("ses", region_name="ap-south-1")

# -------------------- DynamoDB Table References ------------------------
ENTRIES_TABLE          = dynamodb.Table(os.environ["TIME_ENTRIES_TABLE"])
ASSIGNMENTS_TABLE      = dynamodb.Table(os.environ["PROJECT_ASSIGNMENTS_TABLE"])
EMPLOYEE_TABLE         = dynamodb.Table(os.environ["EMPLOYEE_TABLE"])
BACKTRACK_TABLE        = dynamodb.Table(os.environ["BACKTRACK_PERMISSIONS_TABLE"])
PROJECTS_TABLE         = dynamodb.Table(os.environ["PROJECTS_TABLE"])
PTO_TABLE              = dynamodb.Table(os.environ["PTO_TABLE"])
CLIENTS_TABLE          = dynamodb.Table(os.environ["CLIENTS_TABLE"])
APPROVAL_TABLE         = dynamodb.Table(os.environ["APPROVAL_TABLE"])
TASKS_TABLE            = dynamodb.Table(os.environ["TASKS_TABLE"])
USERS_TABLE            = dynamodb.Table(os.environ["USERS_TABLE"])

# ----------------------- S3 Bucket ---------------------------
S3_BUCKET_NAME = os.environ["S3_BUCKET_NAME"]


MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


# -------------------- CORS Headers --------------------
def get_cors_headers(event):
    """
    Returns CORS headers for the response, based on the request's origin.
    If the origin is in the allowlist, uses it. Otherwise, uses "null".
    """
    origin = event.get("headers", {}).get("origin", "")
    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "http://192.168.0.224:3000",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev"
    ]
    if origin in allowed_origins:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
            "Access-Control-Allow-Credentials": "true"
        }
    return {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true"
    }


# -------------------- Build Response --------------------
def build_response(data=None, *, status=200, error=None, message=None, fields=None, error_code=None, event=None):
    body = {}

    if message:
        body["message"] = message
    if error:
        body["error"] = error
        if error_code:
            body["errorCode"] = error_code
        if fields:
            body["fields"] = fields
    elif data is not None:
        body["data"] = data

    return {
        "statusCode": status,
        "headers": get_cors_headers(event or {}),
        "body": json.dumps(body, default=str)
    }



# -------------------- Email Sender via AWS SES --------------------
def send_email(to_email, subject, body_text, body_html=None):
    message = {
        "Subject": {"Data": subject},
        "Body": {"Text": {"Data": body_text}}
    }

    if body_html:
        message["Body"]["Html"] = {"Data": body_html}

    SES.send_email(
        Source=os.environ["SES_SOURCE_EMAIL"],
        Destination={"ToAddresses": [to_email]},
        Message=message
    )


# -------------------- HTML Email Content Builder --------------------
def build_html_email(subject, content_rows):
    rows_html = "".join(
        f"""
        <tr>
            <td style="padding: 10px 14px; font-weight: 600; background-color: #f4f6f8; border: 1px solid #ccc;">{k}</td>
            <td style="padding: 10px 14px; border: 1px solid #ccc;">{v}</td>
        </tr>
        """ for k, v in content_rows.items()
    )

    return f"""
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #ffffff;
            color: #333;
            margin: 0;
            padding: 20px;
        }}
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        h3 {{
            background-color: #007acc;
            color: #fff;
            padding: 16px;
            margin: 0;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 0;
        }}
        td {{
            font-size: 14px;
        }}
      </style>
    </head>
    <body>
      <div class="email-container">
        <h3>{subject}</h3>
        <table>{rows_html}</table>
      </div>
    </body>
    </html>
    """





# -------------------- S3 File Upload Utilities --------------------

def upload_description_to_s3(user_id, project_id, entry_id, base64_data, file_name=None, previous_file_url=None):
    try:
        if not base64_data or not isinstance(base64_data, str):
            return None, "Invalid file format. Expected non-empty Base64 string."

        # Split header and encoded data
        header, encoded = base64_data.split(",", 1) if base64_data.startswith("data:") else ("data:application/octet-stream;base64", base64_data)

        if ";base64" not in header:
            return None, "Invalid Base64 header format."

        content_type = header.split(":", 1)[1].split(";")[0]
        file_bytes = base64.b64decode(encoded)

        # File size check
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            return None, f"File too large. Max {MAX_FILE_SIZE_BYTES // (1024*1024)}MB"

        # Use provided filename or fallback
        if file_name:
            _, ext = os.path.splitext(file_name)
            if not ext:
                ext = mimetypes.guess_extension(content_type) or ".txt"
            safe_name = file_name.replace(" ", "_")
        else:
            ext = mimetypes.guess_extension(content_type) or ".txt"
            safe_name = f"{entry_id}{ext}"

        key = f"descriptions/{user_id}/{project_id}/{safe_name}"

        # Delete old file if URL provided
        if previous_file_url:
            try:
                old_key = previous_file_url.split(f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/")[-1]
                if old_key and old_key != key:
                    s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=old_key)
            except ClientError:
                pass  # Ignore deletion errors

        # Upload to S3
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=key, Body=file_bytes, ContentType=content_type)

        return {
            "url": f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{key}",
            "filename": safe_name,
            "filetype": content_type
        }, None

    except Exception as e:
        return None, f"Upload failed: {e}"




# -------------------- S3 File Delete Utility --------------------

def delete_s3_file(url):
    """
    Delete a file from AWS S3 given its public S3 URL.

    Args:
        url (str): Public S3 URL (https://bucket.s3.amazonaws.com/...) to be deleted.

    Returns:
        None. Prints errors, but does not raise, to avoid breaking main flow.

    Notes:
        - Ignores and prints errors if the file cannot be found or deleted.
        - Use sparingly outside the upload utility to avoid accidental bulk deletion.
    """
    prefix = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/"
    if not url.startswith(prefix):
        return

    key = url[len(prefix):]
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
        print(f"Deleted file: {url}")
    except Exception as e:
        print(f"Failed to delete file {url}: {e}")
        # Not raising exception on purpose





# ——— Backtrack Evaluation Utilities ———

def is_backtrack_required(entry_date_str):
    # Determine if a backtrack approval is required for a given entry date
    entry_date = datetime.strptime(entry_date_str, "%Y-%m-%d").date()
    today = date.today()

    # Current work week boundaries (Mon → Fri)
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=4)

    # Backtrack not required if entry is within this week and today is <= Friday
    if current_week_start <= entry_date <= current_week_end and today <= current_week_end:
        return False

    # Otherwise, require backtrack (past date or outside this week)
    return entry_date < today


def is_backtrack_approved(user_id, project_id, entry_date_str):
    # Check if backtrack is approved for a user/project/date
    if not is_backtrack_required(entry_date_str):
        return True

    resp = BACKTRACK_TABLE.query(
        IndexName="UserProjectIndex",
        KeyConditionExpression=(
            Key("userID").eq(user_id) &
            Key("projectID").eq(project_id)
        ),
        FilterExpression=(
            Attr("entryDates").contains(entry_date_str) &
            Attr("approvalStatus").eq("Approved")
        ),
        Limit=1
    )

    # Return True if at least one approved record exists
    return bool(resp.get("Items"))





# ——— Project Retrieval Utility ———
def get_project(project_id):
    # Retrieve project record by ID, ensuring projectName exists
    resp = PROJECTS_TABLE.get_item(Key={"projectID": project_id})
    project = resp.get("Item")
    if not project:
        return None, build_response(
            error="Invalid Project ID. Project does not exist.",
            fields={"projectID": "Invalid"}
        )
    project["projectName"] = project.get("projectName")
    return project, None


# ——— Get User Name Helper ———
def get_user_name(user_id):
    """Return the full name for a user, checking Employees first, then Users table as fallback."""

    # Check in Employees table
    emp = EMPLOYEE_TABLE.get_item(Key={"employeeID": user_id}).get("Item")
    if emp:
        full_name = f"{emp.get('firstName', '')} {emp.get('lastName', '')}".strip()
        if full_name:
            return full_name

    # Fallback: check in Users table
    usr = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if usr:
        full_name = f"{usr.get('firstName', '')} {usr.get('lastName', '')}".strip()
        if full_name:
            return full_name

    # Final fallback: just return the userID
    return user_id


# ——— Assignment Lookup Utility ———
def get_assignment(user_id: str, project_id: str):
    # Find active assignment for a user + project
    resp = ASSIGNMENTS_TABLE.query(
        IndexName="UserAssignments-index",
        KeyConditionExpression=(
            Key("userID").eq(user_id) &
            Key("projectID").eq(project_id)
        ),
        FilterExpression=Attr("status").eq("Active"),
        Limit=1
    )
    return resp["Items"][0] if resp.get("Items") else None


# ——— Client Name Utility ———
def get_client_name(client_id):
    # Get client companyName or fallback to clientName
    client = CLIENTS_TABLE.get_item(Key={"clientID": client_id}).get("Item")
    if client:
        return client.get("companyName") or client.get("clientName", "")
    return ""


# ——— Miscellaneous Project & Date Utilities ———
def iso_to_weekday_map():
    # Map ISO weekday numbers (0=Mon..6=Sun) to short names
    return {
        0: "mon",
        1: "tue",
        2: "wed",
        3: "thu",
        4: "fri",
        5: "sat",
        6: "sun"
    }

def get_project_name(project_id):
    # Return projectName, or fallback if missing/unknown
    project, _ = get_project(project_id)
    return project.get("projectName", "Unnamed Project") if project else "Unknown Project"




# ——— Get Allowed Record IDs Function ———
def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
    # load user assignments
    assignments = load_user_assignment_records(str(user_id))

    role_names: List[str] = []
    override_rules: List[Dict[str, Any]] = []

    # collect overrides and roles
    for rec in assignments:
        ovID = str(rec.get("ovID") or rec.get("SK") or "")
        status = rec.get("Status") or rec.get("status") or "active"

        if status != "active":
            continue

        if ovID.startswith("B#OVR#") and rec.get("module") == module:
            allow = rec.get("Allow") or {}
            deny = rec.get("Deny") or {}
            override_rules.extend(convert_permissions_dict_to_rules("allow", allow, rec))
            override_rules.extend(convert_permissions_dict_to_rules("deny", deny, rec))
        elif ovID.startswith("A#ROLE#"):
            role_name = ovID.split("#", 2)[2]
            role_names.append(role_name)

    # load role rules
    role_rules: List[Dict[str, Any]] = []
    for role in role_names:
        rules_for_role = extract_role_permission_rules_for_module(role, module)
        role_rules.extend(rules_for_role)

    # merge overrides and roles
    if override_rules:
        override_actions = {rule["action"] for rule in override_rules}
        combined_rules = [r for r in role_rules if r["action"] not in override_actions]
        combined_rules.extend(override_rules)
    else:
        combined_rules = role_rules

    scopes: List[str] = []
    selected_ids: set[str] = set()
    allow_all = False

    # evaluate combined rules
    for rule in combined_rules:
        if not check_action_pattern_match(rule.get("action", "*"), action):
            continue

        entries = rule.get("_entry") or []
        if isinstance(entries, list):
            for scope in entries:
                if scope == "all":
                    allow_all = True
                else:
                    scopes.append(scope)

        if "selected" in entries and "_selectedIds" in rule:
            selected_ids.update(map(str, rule["_selectedIds"]))

    return {
        "all": allow_all,
        "ids": selected_ids or None,
        "scopes": list(set(scopes)),  # dedupe
        "pattern": action,
    }




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
    """Evaluate access decision and return a 403 response if denied (only error message)."""

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

    if decision.get("decision") == "DENY":
        reason = decision.get("reason") or "explicit deny"
        return build_response(
            data={"error": f"Not authorized to {resource}.{action} ({reason})"},
            status=403,
            event=event,
        )

    return None
