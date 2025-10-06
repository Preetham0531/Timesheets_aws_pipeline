import boto3
import json
import os
import logging
from boto3.dynamodb.conditions import Key, Attr

from datetime import datetime, timedelta

# -------------------- Logger Configuration --------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# -------------------- AWS Clients & Resources --------------------
dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")

# -------------------- DynamoDB Table References --------------------
USERS_TABLE           = dynamodb.Table(os.environ["USERS_TABLE"])
PROJECTS_TABLE        = dynamodb.Table(os.environ["PROJECTS_TABLE"])
ENTRIES_TABLE         = dynamodb.Table(os.environ["TIME_ENTRIES_TABLE"])
EMPLOYEES_TABLE       = dynamodb.Table(os.environ["EMPLOYEE_TABLE"])
TASKS_TABLE           = dynamodb.Table(os.environ["TASKS_TABLE"])


# -------------------- SES Sender Email --------------------
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "noreply@example.com")


# -------------------- CORS Headers --------------------
def get_cors_headers(event):
    """
    Returns CORS headers for an AWS Lambda/API Gateway response.

    Normalizes both 'origin' and 'Origin' headers, removes a trailing slash,
    and checks against the allowed origins list.
    If allowed, responds with the matched origin; if not, returns 'null'.

    Args:
        event (dict): API Gateway event. Should include an HTTP 'headers' dictionary.

    Returns:
        dict: A dictionary of CORS headers (plus content-type), suitable for API Gateway/Lambda proxy output.
    """
    origin = (
        event.get("headers", {}).get("origin")
        or event.get("headers", {}).get("Origin")
        or ""
    )
    # Normalize by removing any trailing slash
    origin = origin.rstrip("/") if origin else ""
    
    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "https://labs.inferai.ai",
        "https://www.labs.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev"
    ]

    if origin in allowed_origins:
        return {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,GET,POST,PUT,DELETE",
            "Access-Control-Allow-Credentials": "true"
        }

    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,GET,POST,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true"
    }



# -------------------- Response Builder --------------------

def build_response(*args, data=None, status=200, error=None, fields=None, **kwargs):
    """
    Assemble a REST API Gateway-compatible response.

    - Supports both build_response(event, ...) and build_response(..., event=event).
    - Applies CORS headers based on the event using get_cors_headers.
    - If error is present: returns {"error": ...} (and optional 'fields').
    - Automatically picks status 400/403/401 for common error types if status is left 200.
    - If no error: returns 'data' as the body (or an empty dict by default).
    - Always uses json.dumps(body, default=str) to ensure serializability.

    Args:
        event (dict): The original API Gateway/Lambda event (for CORS header context).
        data (dict, optional): On success, the body data to return.
        status (int, optional): HTTP status (defaults to 200, but will update for errors if needed).
        error (str, optional): Error string.
        fields (dict, optional): Validation details or extra info.

    Returns:
        dict: API Gateway-compatible response dict (statusCode, headers, body).
    """
    # Accept event from either positional or keyword
    event = None
    if args:
        event = args[0]
    if "event" in kwargs:
        # keyword event wins if both provided
        event = kwargs.pop("event")

    headers = get_cors_headers(event or {})

    if error:
        body = {"error": error}
        if fields:
            body["fields"] = fields
        if status == 200:
            # If user forgot to set a non-200 status, default based on error
            status = (
                400 if error == "Validation error"
                else 403 if error == "Forbidden"
                else 401
            )
    else:
        body = data or {}

    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body, default=str)
    }



# -------------------- Authorization Helper --------------------

def get_user_id(user: dict) -> str | None:
    """
    Normalize user identity across different shapes of user context.
    Supports JWT (`sub`) and authorizer (`user_id`).
    """
    return user.get("user_id") or user.get("sub") or user.get("id") or user.get("userID")


# -------------------- User & Project Helpers --------------------

def get_user_email(user_id):
    """
    Fetch the email address for a given user ID.

    Args:
        user_id (str): The user's unique ID.
    Returns:
        str: User's email address if found, otherwise an empty string.
    """
    return USERS_TABLE.get_item(Key={"userID": user_id}).get("Item", {}).get("email", "")

def get_user_full_name(user_id: str) -> str:
    """
    Resolve a human-friendly name for a user/employee.

    Order of resolution:
      1) Employees table: firstName + lastName
      2) Employees table fallback: officialEmail -> secondaryEmail -> displayID
      3) Users table: firstName + lastName
      4) Users table fallback: email
      5) Shortened ID

    Returns a non-empty string; never "Unknown User".
    """
    # --- 1) Employees table (preferred) ---
    try:
        emp = EMPLOYEES_TABLE.get_item(
            Key={"employeeID": user_id},
            ProjectionExpression="firstName,lastName,officialEmail,secondaryEmail,displayID"
        ).get("Item") or {}

        first = (emp.get("firstName") or "").strip()
        last  = (emp.get("lastName") or "").strip()

        if first or last:
            return f"{first} {last}".strip()

        for k in ("officialEmail", "secondaryEmail", "displayID"):
            v = (emp.get(k) or "").strip()
            if v:
                return v
    except Exception:
        pass  # fall through safely

    # --- 2) Users table (legacy / fallback) ---
    try:
        user = USERS_TABLE.get_item(
            Key={"userID": user_id},
            ProjectionExpression="firstName,lastName,email"
        ).get("Item") or {}

        first = (user.get("firstName") or "").strip()
        last  = (user.get("lastName") or "").strip()
        if first or last:
            return f"{first} {last}".strip()

        email = (user.get("email") or "").strip()
        if email:
            return email
    except Exception:
        pass

    # --- 3) Final fallback: short ID ---
    return f"User {str(user_id)[:8]}"


def get_project_name(project_id):
    """
    Get the name of a project by its ID. Handles legacy casing.
    Returns "Unknown Project" if not found.

    Args:
        project_id (str): The project unique identifier.
    Returns:
        str: Project name or "Unknown Project"
    """
    if not project_id:
        return "Unknown Project"
    try:
        item = PROJECTS_TABLE.get_item(Key={"projectID": project_id}).get("Item")
        if not item:
            # some legacy Dynamo tables use 'projectId' lowercase
            item = PROJECTS_TABLE.get_item(Key={"projectId": project_id}).get("Item")
        return item.get("projectName", "Unknown Project") if item else "Unknown Project"
    except Exception as e:
        logger.error(f"Error in get_project_name: {e}")
        return "Unknown Project"

from boto3.dynamodb.conditions import Key

def get_task_name_by_id(task_id: str) -> str:
    """
    Fetch task name from TASKS_TABLE using taskID.
    
    Args:
        task_id (str): The task ID to look up
        
    Returns:
        str: Task name if found, otherwise "Unknown Task"
    """
    if not task_id:
        return "Unknown Task"
    
    try:
        task_resp = TASKS_TABLE.get_item(Key={"taskID": task_id})
        task_item = task_resp.get("Item")
        
        if task_item:
            task_name = task_item.get("taskName") or task_item.get("TaskName")
            if task_name:
                return task_name
            
    except Exception as e:
        logger.error(f"Error fetching task name for taskID {task_id}: {e}")
    
    return "Unknown Task"

def resolve_task_name(entry_data: dict) -> str:
    """
    Resolve task name from entry data with comprehensive fallback logic.
    
    Priority order:
    1. TASKS_TABLE lookup using taskID (most reliable)
    2. Direct taskName/TaskName field in entry
    3. Legacy Task field in entry
    4. "Unknown Task" fallback
    
    Args:
        entry_data (dict): Time entry data containing taskID and/or task name fields
        
    Returns:
        str: Resolved task name
    """
    # PRIORITY 1: TASKS_TABLE lookup using taskID
    task_id = entry_data.get("taskID") or entry_data.get("TaskID")
    if task_id:
        task_name = get_task_name_by_id(task_id)
        if task_name != "Unknown Task":
            return task_name
    
    # PRIORITY 2: Direct task name fields in entry
    task_name = (
        entry_data.get("taskName") or 
        entry_data.get("TaskName") or 
        entry_data.get("Task") or 
        "Unknown Task"
    )
    
    return task_name

def get_time_entry_info(entry_id: str) -> dict:
    """
    Query the 'TimeEntryID-index' to retrieve a single time entry,
    then fetch the task name using taskID from the tasks table.
    """
    try:
        resp = ENTRIES_TABLE.query(
            IndexName="TimeEntryID-index",
            KeyConditionExpression=Key("TimeEntryID").eq(entry_id)
        )
        items = resp.get("Items", [])
        if not items:
            return {
                "project_id":   "",
                "project_name": "Unknown Project",
                "owner_id":     "",
                "date":         "Unknown",
                "task":         "Unknown Task",
                "regular":      0,
                "overtime":     0,
                "total":        0
            }

        item = items[0]

        # Project name
        project_name = (
            item.get("projectName")
            or get_project_name(item.get("projectID", ""))
            or "Unknown Project"
        )

        # Task name resolution using new resolver
        task_name = resolve_task_name(item)

        return {
            "project_id":   item.get("projectID", ""),
            "project_name": project_name,
            "owner_id":     item.get("UserID", ""),
            "date":         item.get("Date") or item.get("WeekStartDate") or "Unknown",
            "task":         task_name,
            "regular":      float(item.get("RegularHours", 0) or 0),
            "overtime":     float(item.get("OvertimeHours", 0) or 0),
            "total":        float(item.get("TotalHoursWorked", 0) or 0)
        }

    except Exception as e:
        logger.error(f"get_time_entry_info error: {e}")
        return {
            "project_id":   "",
            "project_name": "Unknown Project",
            "owner_id":     "",
            "date":         "Unknown",
            "task":         "Unknown Task",
            "regular":      0,
            "overtime":     0,
            "total":        0
        }


# -------------------- Email Utility --------------------

def build_html_email(subject: str, body_content: str) -> str:
    """
    Wraps plain HTML body_content inside a styled HTML email template.

    Args:
        subject (str): Subject/title for the email, used as the banner.
        body_content (str): HTML-formatted content (e.g., table, message block).

    Returns:
        str: The complete HTML email content with inline styles, ready for SES or SMTP.
    """
    return f"""
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            margin: 0;
            padding: 30px;
        }}
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }}
        h3 {{
            background-color: #007acc;
            color: #ffffff;
            padding: 18px 24px;
            margin: 0;
            font-size: 18px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        }}
        .content {{
            padding: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }}
        th, td {{
            padding: 8px;
            border: 1px solid #ccc;
            text-align: left;
        }}
        .footer {{
            margin-top: 20px;
            font-size: 14px;
            color: #555;
        }}
      </style>
    </head>
    <body>
      <div class="email-container">
        <h3>{subject}</h3>
        <div class="content">
          {body_content}
        </div>
      </div>
    </body>
    </html>
    """

def send_email(to_email: str, subject: str, plain_text: str, html_content: str):
    """
    Sends a multipart email (plain-text and styled HTML) using AWS SES.

    Args:
        to_email (str): Recipient's email address.
        subject (str): Subject line for the email.
        plain_text (str): Fallback plain text content.
        html_content (str): Main HTML content (will be in the styled template).

    Notes:
        - Sets the sender as 'Timesheets <SES_SENDER_EMAIL>'.
        - HTML is wrapped via build_html_email, so you can provide any table or message HTML as html_content.
    """
    ses.send_email(
        Source=f"Timesheets <{SES_SENDER_EMAIL}>",
        Destination={"ToAddresses": [to_email]},
        Message={
            "Subject": {"Data": subject},
            "Body": {
                "Text": {"Data": plain_text},
                "Html": {"Data": build_html_email(subject, html_content)}
            }
        }
    )



# -------------------- Date-Range & Privilege Helpers --------------------

def get_date_range(range_type):
    """
    Returns (start_date, end_date) date objects for a named range type.

    Args:
        range_type (str): One of "this week", "last week", "this month", "last month".
            - "this week": Mon-Sun of the current week (ISO standard, week starts on Monday).
            - "last week": Mon-Sun of the previous week.
            - "this month": 1st to last day of current month.
            - "last month": 1st to last day of previous month.

    Returns:
        tuple: (start_date, end_date) as datetime.date objects, or (None, None) if range_type not recognized.
    """
    today = datetime.utcnow().date()

    if range_type == "this week":
        start = today - timedelta(days=today.weekday())
        end   = start + timedelta(days=6)
    elif range_type == "last week":
        end   = today - timedelta(days=today.weekday() + 1)
        start = end - timedelta(days=6)
    elif range_type == "this month":
        start = today.replace(day=1)
        end   = (start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    elif range_type == "last month":
        first_day_this_month = today.replace(day=1)
        end   = first_day_this_month - timedelta(days=1)
        start = end.replace(day=1)
    else:
        return None, None

    return start, end



def fmt(total: float) -> str:
    """
    Converts hours (as a float) into a HH:MM:00 zero-padded string.

    Args:
        total (float): Total hours, e.g., 2.5 for 2 hours 30 mins.

    Returns:
        str: String in "HH:MM:00" format (e.g., "02:30:00").
    """
    hh = int(total)
    mm = int(round((total - hh) * 60))
    return f"{hh:02}:{mm:02}:00"
