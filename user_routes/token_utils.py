# -------------------- IMPORTS --------------------
import os
import jwt
import json
import boto3
from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Key, Attr
from http.cookies import SimpleCookie
# from token_utils import *

# -------------------- CONFIG --------------------
JWT_SECRET    = os.environ["JWT_SECRET"]
FRONTEND_URL  = os.environ.get("FRONTEND_URL")

# -------------------- DYNAMODB RESOURCES --------------------
dynamodb = boto3.resource("dynamodb")
s3       = boto3.client("s3")

USERS_TABLE           = dynamodb.Table(os.environ["USERS_TABLE"])
CREDENTIALS_TABLE     = dynamodb.Table(os.environ["CREDENTIALS_TABLE"])
CLIENTS_TABLE         = dynamodb.Table(os.environ["CLIENTS_TABLE"])
EMPLOYEES_TABLE       = dynamodb.Table(os.environ["EMPLOYEES_TABLE"])
ROLES_TABLE           = dynamodb.Table(os.environ.get("ROLE_POLICIES_TABLE"))
ROLE_BY_NAME_INDEX    = os.environ.get("ROLE_BY_NAME_INDEX")
USERGRANTS_TABLE      = dynamodb.Table(os.environ.get("USERGRANTS_TABLE"))

# -------------------- REFRESH TOKEN --------------------
def get_refresh_token_from_cookie(event):
    cookie_header = event.get("headers", {}).get("cookie", "")
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    return cookie["refreshToken"].value if "refreshToken" in cookie else None

# -------------------- GENERATE TOKENS --------------------
def generate_token(user_id, email, role, minutes):
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

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

# -------------------- API RESPONSE BUILDER --------------------
def build_response(data=None, *, status=200, error=None, message=None, cookies=None):
    body = {"error": error} if error else (data or {})
    if message:
        body["message"] = message

    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": FRONTEND_URL,
        "Access-Control-Allow-Credentials": "true"
    }
    if cookies:
        headers["Set-Cookie"] = cookies

    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body)
    }

# -------------------- FIND CREDENTIALS --------------------
def find_user_by_email_or_username(identifier):
    # ——— Try Email First (via GSI_Email) ———
    email_query = USERS_TABLE.query(
        IndexName="GSI_Email",
        KeyConditionExpression=Key("officialEmail").eq(identifier)
    )
    if email_query.get("Items"):
        return email_query["Items"][0]

    # ——— Try Username (via GSI_Username) ———
    username_query = USERS_TABLE.query(
        IndexName="GSI_Username",
        KeyConditionExpression=Key("username").eq(identifier)
    )
    items = username_query.get("Items", [])
    if items:
        return items[0]

    return None



# -------------------- CORS HEADERS --------------------
def get_cors_headers(event):
    origin_header = (event.get("headers") or {}).get("origin", "")

    allowed_origins = {
        "http://localhost:3000",
        "http://192.168.0.224:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://test.d2zasimyd0ou3m.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://a3e2b2de68ff4c12a3ec9e2d6290b90f-0d615ee1558e4bc09694b8d76.fly.dev",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.projects.builder.codes",
        "https://a3e2b2de68ff4c12a3ec9e2d6290b90f-0d615ee1558e4bc09694b8d76.projects.builder.codes",
        "https://timesheetdemo.netlify.app",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "https://labs.inferai.ai",
        "https://www.labs.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://testing.d1mrwdhut31a27.amplifyapp.com",
        "http://localhost:48752",
        "https://cdc836e8d07349b59ea0de4d605de474-fb66ff6d-699b-41d4-9d3c-36e04e.fly.dev",
        "https://cdc836e8d07349b59ea0de4d605de474-fb66ff6d-699b-41d4-9d3c-36e04e.projects.builder.codes",
        "https://349e5285ba844602863553cdc01e0ced-af93e97b-8b8e-4671-a86e-745f2d.fly.dev",
        "https://4b6630838806464890bf8ea4ba2ad31a-c057f8d4-bbc5-496d-bf39-1f9dc0.fly.dev",
        "https://4b6630838806464890bf8ea4ba2ad31a-c057f8d4-bbc5-496d-bf39-1f9dc0.projects.builder.codes",
        "http://192.168.1.14:3000",
        "https://4b5767e1c05f4d0699b39d50c65a9945-b22402c5-3914-4c1f-9db6-bb12c5.fly.dev",
        "https://4b5767e1c05f4d0699b39d50c65a9945-b22402c5-3914-4c1f-9db6-bb12c5.projects.builder.codes",
        "https://8591874e18fd4ddaa26872cf97a9e1e6-dc9164ba-2cc9-4fb2-92b4-50499e.fly.dev",
        "https://f4e9513b65944621aae703b47ba05dbd-2b972ad1-3949-4d01-a73a-ce20a1.fly.dev",
        "https://536ea62836d74f228f9055e5dac8d43b-e8965395-d584-49ba-859d-fdd967.projects.builder.codes",
        "https://536ea62836d74f228f9055e5dac8d43b-e8965395-d584-49ba-859d-fdd967.fly.dev",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.projects.builder.codes",
    "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.fly.dev"
    }

    cors_origin = origin_header if origin_header in allowed_origins else "*"
    return {
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST",
        "Access-Control-Allow-Credentials": "true"
    }







# ——— Get Viewable Modules API ———
def get_viewable_modules(user_id: str, role_names: list[str]) -> list[str]:
    """
    Merge module view access from UserGrants (overrides) and Roles table.

    Rules:
    - UserGrants take precedence over role-level access.
    - Only the most recent override per module is applied (updatedAt > createdAt).
    - Excludes "none" values, even if provided inside lists.
    - If an override exists (even 'none'), it fully suppresses role-level policies for that module.
    - For TimeEntries, module access is decided ONLY by records_view (not allow.view).
    """

    modules_with_view_access = set()      # Final allowed modules
    overridden_modules = set()            # Modules with overrides (deny or allow)
    valid_view_values = ["all", "self", "selected", "selected_by_creator"]

    # ——— Load UserGrants overrides ———
    try:
        resp = USERGRANTS_TABLE.query(
            KeyConditionExpression=Key("userID").eq(user_id) & Key("ovID").begins_with("B#OVR#MODULE#"),
        )
        user_overrides = resp.get("Items", []) or []
    except Exception:
        user_overrides = []

    # ——— Deduplicate: keep only the latest override per module ———
    latest_override_per_module = {}
    for override in user_overrides:
        if (override.get("Status") or override.get("status", "")).lower() != "active":
            continue

        module_name = override.get("module")
        if not module_name:
            continue

        updated_at = override.get("updatedAt") or override.get("createdAt")
        if updated_at:
            updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        else:
            updated_at = datetime.min

        if (
            module_name not in latest_override_per_module
            or updated_at > latest_override_per_module[module_name][1]
        ):
            latest_override_per_module[module_name] = (override, updated_at)

    user_overrides = [v[0] for v in latest_override_per_module.values()]

    # ——— Apply UserGrants overrides ———
    for override in user_overrides:
        module_name = override.get("module")
        overridden_modules.add(module_name)   # Mark this module as overridden

        allow_rules = override.get("Allow", {})
        deny_rules = override.get("Deny", {})

        # TimeEntries special case: check only records_view
        if module_name == "TimeEntries":
            records_view = allow_rules.get("records_view")
            if "records_view" in deny_rules:
                continue
            if (
                records_view == "all"
                or records_view == "self"
                or records_view == "selected"
                or (isinstance(records_view, list) and any(v in ["all", "self", "selected"] for v in records_view))
            ):
                modules_with_view_access.add("TimeEntries")
            continue

        # Normal modules
        view_conf = allow_rules.get("view")

        if "view" in deny_rules:
            continue

        if isinstance(view_conf, str) and view_conf in valid_view_values:
            modules_with_view_access.add(module_name)

        elif isinstance(view_conf, list):
            cleaned = [v for v in view_conf if v in valid_view_values]
            if cleaned:
                modules_with_view_access.add(module_name)

        elif isinstance(view_conf, dict) and (
            ("selected" in view_conf and view_conf["selected"])
            or ("selected_by_creator" in view_conf and view_conf["selected_by_creator"])
        ):
            modules_with_view_access.add(module_name)

    # ——— Fallback to Role-level policies (if not overridden) ———
    for role_name in role_names:
        try:
            query_response = ROLES_TABLE.query(
                IndexName=ROLE_BY_NAME_INDEX,
                KeyConditionExpression=Key("role").eq(role_name),
                Limit=1,
            )
            role_items = query_response.get("Items", []) or []
        except Exception:
            role_items = []

        if not role_items:
            continue

        role_policies = role_items[0].get("Policies", {})
        if isinstance(role_policies, str):
            try:
                role_policies = json.loads(role_policies)
            except Exception:
                role_policies = {}

        # Check each module in role policies
        for module_name, module_policy in (role_policies or {}).items():
            if module_name in overridden_modules:  # Skip if override exists
                continue
            if not isinstance(module_policy, dict):
                continue

            allow_rules = module_policy.get("allow", {})
            deny_rules = module_policy.get("deny", {})

            # TimeEntries special case: check only records_view
            if module_name == "TimeEntries":
                records_view = allow_rules.get("records_view")
                if "records_view" in deny_rules:
                    continue
                if (
                    records_view == "all"
                    or records_view == "self"
                    or records_view == "selected"
                    or (isinstance(records_view, list) and any(v in ["all", "self", "selected"] for v in records_view))
                ):
                    modules_with_view_access.add("TimeEntries")
                continue

            # Normal modules
            view_conf = allow_rules.get("view")

            if "view" in deny_rules:
                continue

            if isinstance(view_conf, str) and view_conf in valid_view_values:
                modules_with_view_access.add(module_name)

            elif isinstance(view_conf, list):
                cleaned = [v for v in view_conf if v in valid_view_values]
                if cleaned:
                    modules_with_view_access.add(module_name)

            elif isinstance(view_conf, dict) and (
                ("selected" in view_conf and view_conf["selected"])
                or ("selected_by_creator" in view_conf and view_conf["selected_by_creator"])
            ):
                modules_with_view_access.add(module_name)

    # ——— Final Response ———
    return sorted(list(modules_with_view_access))
