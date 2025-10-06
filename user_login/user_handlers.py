
import base64
import json
import os
import uuid
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set
from policy_engine import evaluate, AccessRequest


# Third-party libraries
import bcrypt
import boto3
import jwt
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from email_utils import *
from utils import *
from utils import decision_or_deny


S3 = boto3.client("s3")
RESET_LINK_BASE_URL = "https://timesheets.dev.inferai.ai"


# ——— Promote Employee To User ———
def promote_Employee_To_User(event, request_body, auth_context):
    # ——— Requester validation ———
    requester_user_id = auth_context.get("user_id")
    if not requester_user_id:
        return build_response(event, status=401, error="Missing requester identity")

    # ——— Input extraction ———
    employee_id      = request_body.get("employeeID")
    username         = (request_body.get("username") or "").lower()
    requested_rids   = request_body.get("roleids") or []
    replace_existing = bool(request_body.get("replace", False))
    first_name       = request_body.get("firstName", "")
    last_name        = request_body.get("lastName", "")
    email_address    = (request_body.get("officialEmail") or "").lower()
    plain_password   = request_body.get("password")

    # ——— Privacy inputs ———
    is_private       = bool(request_body.get("private", False))
    allowed_users    = request_body.get("allowedUsers") or []

    # Normalize allowed users
    if not isinstance(allowed_users, list):
        return build_response(event, status=400, error="allowedUsers must be a list if provided")

    # ——— Basic validations ———
    if not username:
        return build_response(event, status=400, error="Missing required field: username")
    if not requested_rids:
        return build_response(event, status=400, error="Provide roleids[]")
    if not isinstance(requested_rids, list) or not all(isinstance(rid, str) for rid in requested_rids):
        return build_response(event, status=400, error="roleids must be an array of role IDs")

    # ——— Validate role IDs ———
    valid_rids   = set(validateRoleIdsExist(requested_rids))
    invalid_rids = [rid for rid in requested_rids if rid not in valid_rids]
    if invalid_rids:
        return build_response(event, status=400, data={"error": "Unknown rids", "missing": invalid_rids})

    chosen_rids  = set(valid_rids)
    rid_to_role  = {}
    for rid in chosen_rids:
        resp = ROLES_TABLE.query(
            KeyConditionExpression=Key("rid").eq(rid),
            ProjectionExpression="#r",
            ExpressionAttributeNames={"#r": "role"}
        ).get("Items", [])
        if resp:
            rid_to_role[rid] = resp[0]["role"]

    chosen_roles = set(rid_to_role.values())

    # ——— Permission check: must be allowed to create Users ———
    deny = decision_or_deny(
        event,
        requester_user_id,
        "Users",
        "create",
        record_id=requester_user_id,
        record_type="user",
        resource_object={"username": username}
    )
    if deny:
        return deny

    # ——— Uniqueness checks ———
    existing_user = USERS_TABLE.query(
        IndexName="GSI_Username",
        KeyConditionExpression=Key("username").eq(username),
        ProjectionExpression="userID"
    ).get("Items", [])
    if existing_user:
        return build_response(event, status=400, error="Username already in use")

    if email_address:
        email_conflict = USERS_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email_address),
            ProjectionExpression="userID"
        ).get("Items", [])
        if email_conflict:
            return build_response(event, status=400, error="Email already in use")

    # ——— Base user item ———
    created_at = datetime.utcnow().isoformat()
    user_item = {
        "userID": str(employee_id) if employee_id else generate_uuid(),
        "username": username,
        "roles": sorted(list(chosen_roles)),
        "rids": sorted(list(chosen_rids)),
        "createdAt": created_at,
        "createdBy": requester_user_id,
        "updatedAt": created_at,
        "updatedBy": requester_user_id,
        "private": is_private,
        "allowedUsers": list(set(allowed_users + [requester_user_id])) if is_private else [],
    }

    if not employee_id:
        user_item["firstName"] = first_name
        user_item["lastName"]  = last_name

    setup_token, setup_link = None, None
    deactivated_roles = []

    # ——— Old approach (employeeID) ———
    if employee_id:
        employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": employee_id}).get("Item")
        if not employee_record:
            return build_response(event, status=404, error="Employee not found")
        if employee_record.get("loginEnabled"):
            return build_response(event, status=400, error="Employee already has login access")

        deny = decision_or_deny(
            event,
            requester_user_id,
            "Employees",
            "view",
            record_id=employee_id,
            record_type="employee",
            resource_object=employee_record
        )
        if deny:
            return deny

        email_address = employee_record["officialEmail"].lower()
        setup_token   = generate_setup_or_reset_token(user_item["userID"], email_address, "setup", 120)
        setup_link    = f"{os.environ['FRONTEND_URL']}/set-password/?token={setup_token}"

        user_item.update({
            "employeeID": employee_id,
            "displayID": employee_record.get("displayID", ""),
            "officialEmail": email_address,
            "status": "Pending",
            "passwordHash": "",
            "approach": "old",
            "private": is_private,
            "allowedUsers": list(set(allowed_users + [requester_user_id])) if is_private else [],
        })

    # ——— New email approach ———
    elif email_address:
        employee_conflict = EMPLOYEES_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email_address),
            ProjectionExpression="employeeID"
        ).get("Items", [])
        if employee_conflict:
            return build_response(event, status=400, error="Email already associated with an Employee")

        display_id   = generate_unique_display_id("EMP")
        setup_token  = generate_setup_or_reset_token(user_item["userID"], email_address, "setup", 120)
        setup_link   = f"{os.environ['FRONTEND_URL']}/set-password/?token={setup_token}"

        user_item.update({
            "displayID": display_id,
            "officialEmail": email_address,
            "status": "Pending",
            "passwordHash": "",
            "approach": "new_email",
            "private": is_private,
            "allowedUsers": list(set(allowed_users + [requester_user_id])) if is_private else [],
        })

    # ——— New password approach ———
    else:
        if not plain_password:
            return build_response(event, status=400, error="Password is required when no email/employeeID provided")

        hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode("utf-8")
        display_id      = generate_unique_display_id("EMP")

        user_item.update({
            "displayID": display_id,
            "status": "Active",
            "loginEnabled": True,
            "passwordHash": hashed_password,
            "approach": "new_password",
            "private": is_private,
            "allowedUsers": list(set(allowed_users + [requester_user_id])) if is_private else [],
        })

    # ——— Insert user record ———
    USERS_TABLE.put_item(Item=user_item)

    # ——— Assign roles ———
    current_assignments = fetchCurrentRoleAssignments(user_item["userID"])
    active_roles_before = {
        str(assignment.get("role"))
        for assignment in current_assignments
        if str(assignment.get("status", "active")).lower() == "active"
        or str(assignment.get("Status", "active")).lower() == "active"
    }

    for rid, role_name in rid_to_role.items():
        putRoleAssignment(user_item["userID"], rid, role_name, requester_user_id)

    if replace_existing:
        roles_to_deactivate = active_roles_before - chosen_roles
        for role_name in roles_to_deactivate:
            rid = next((r for r, rn in rid_to_role.items() if rn == role_name), None)
            if rid:
                deactivateRoleAssignment(user_item["userID"], rid, role_name)
                deactivated_roles.append(role_name)

    # ——— Send setup email if needed ———
    if setup_token and email_address:
        full_name = f"{first_name} {last_name}".strip() or get_user_full_name(user_item["userID"])
        subject   = "Welcome – Set Up Your Password"
        html_body, text_body = render_invitation_email(
            setup_link=setup_link,
            user_email=email_address,
            full_name=full_name
        )
        send_email(
            recipient_email=email_address,
            subject=subject,
            html_content=html_body,
            text_content=text_body
        )

    # ——— Final response ———
    return build_response(
        event,
        status=200,
        data={
            "message": "User account created successfully.",
            "userID": user_item["userID"],
            "private": is_private,
            "allowedUsers": user_item.get("allowedUsers", []),
        }
    )










# ——— Get Users ———
def handle_get_users(event, caller_id: str):
    query_params = event.get("queryStringParameters") or {}
    user_id = query_params.get("userID")

    # Single user
    if user_id:
        resp = USERS_TABLE.get_item(Key={"userID": user_id})
        record = resp.get("Item")
        if not record:
            return build_response(event, error="User not found", status=404)

        deny = decision_or_deny(
            event,
            caller_id,
            "Users",
            "view",
            record_id=user_id,
            record_type="user",
            resource_object=record,
        )
        if deny:
            return deny

        sanitized = sanitize_user_record(record)
        sanitized["linkedEmployeeName"] = get_user_full_name(user_id)
        sanitized["roleID"] = get_primary_role_id(sanitized.get("roles", []))

        if record.get("createdBy"):
            sanitized["createdByName"] = get_user_full_name(record["createdBy"])
        if record.get("updatedBy"):
            sanitized["updatedByName"] = get_user_full_name(record["updatedBy"])

        return build_response(event, data={"user": sanitized, "status": 200})

    # List users
    scan_args = {"Limit": 150}
    if last_key := query_params.get("lastKey"):
        scan_args["ExclusiveStartKey"] = {"userID": last_key}

    scan_response = USERS_TABLE.scan(**scan_args)
    records = scan_response.get("Items", []) or []
    last_key_value = scan_response.get("LastEvaluatedKey", {}).get("userID")

    filtered_records = []
    for record in records:
        deny = decision_or_deny(
            event,
            caller_id,
            "Users",
            "view",
            record_id=record.get("userID"),
            record_type="user",
            resource_object=record,
        )
        if not deny:
            sanitized = sanitize_user_record(record)

            user_id_val = record.get("userID")
            if user_id_val:
                sanitized["linkedEmployeeName"] = get_user_full_name(user_id_val)

            sanitized["roleID"] = get_primary_role_id(sanitized.get("roles", []))

            if record.get("createdBy"):
                sanitized["createdByName"] = get_user_full_name(record["createdBy"])
            if record.get("updatedBy"):
                sanitized["updatedByName"] = get_user_full_name(record["updatedBy"])

            filtered_records.append(sanitized)

    return build_response(
        event,
        data={
            "users": filtered_records,
            "total": len(filtered_records),
            "lastKey": last_key_value,
            "status": 200,
        },
    )






# -------------------- Update Employee --------------------
def update_user_record(event, user_id: str, body: dict, caller_id: str):
    """
    Update user data.
    - Enforces Users.view + Users.modify (self, selected, deny, all)
    - Checks duplicate officialEmail using GSI_Email
    - Checks duplicate username using GSI_Username
    - Syncs officialEmail into Employees table as well
    """

    # ——— Load Target Record ———
    resp = USERS_TABLE.get_item(Key={"userID": user_id})
    user_record = resp.get("Item")
    if not user_record:
        return build_response(event, status=404, error="User not found")

    # ——— Policy Enforcement: Users.view ———
    deny = decision_or_deny(
        event,
        caller_id,
        "Users",
        "view",
        record_id=user_id,
        record_type="user",
        resource_object=user_record,
    )
    if deny:
        return deny

    # ——— Policy Enforcement: Users.modify ———
    deny = decision_or_deny(
        event,
        caller_id,
        "Users",
        "modify",
        record_id=user_id,
        record_type="user",
        resource_object=user_record,
    )
    if deny:
        return deny

    # ——— Allowed Fields ———
    user_fields = ["username", "status", "officialEmail"]
    update_fields = {k: body[k] for k in user_fields if k in body}

    if not update_fields:
        return build_response(
            event,
            status=400,
            error="No valid fields provided for update"
        )

    now_iso = datetime.utcnow().isoformat()
    update_fields.update({"updatedAt": now_iso, "updatedBy": caller_id})

    # ——— Duplicate Email Check (GSI_Email) ———
    if "officialEmail" in body:
        email = body["officialEmail"].lower().strip()

        user_items = USERS_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="userID"
        ).get("Items", [])

        employee_items = EMPLOYEES_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="employeeID"
        ).get("Items", [])

        for rec in (user_items or []) + (employee_items or []):
            existing_id = rec.get("userID") or rec.get("employeeID")
            if existing_id and existing_id != user_id:
                return build_response(
                    event,
                    error="Duplicate officialEmail",
                    data={"officialEmail": "Email already in use"},
                    status=409,
                )

    # ——— Duplicate Username Check (GSI_Username) ———
    if "username" in body:
        username = body["username"].lower().strip()

        user_items = USERS_TABLE.query(
            IndexName="GSI_Username",
            KeyConditionExpression=Key("username").eq(username),
            ProjectionExpression="userID"
        ).get("Items", [])

        for rec in user_items or []:
            existing_id = rec.get("userID")
            if existing_id and existing_id != user_id:
                return build_response(
                    event,
                    error="Duplicate username",
                    data={"username": "Username already in use"},
                    status=409,
                )

    # ——— Build Update Expression ———
    def build_update_params(fields_dict):
        RESERVED = {"status"}
        set_clauses, expr_vals, expr_names = [], {}, {}
        for key, val in fields_dict.items():
            placeholder = f"#{key}" if key in RESERVED else key
            if key in RESERVED:
                expr_names[placeholder] = key
            set_clauses.append(f"{placeholder} = :{key}")
            expr_vals[f":{key}"] = val
        return {
            "UpdateExpression": "SET " + ", ".join(set_clauses),
            "ExpressionAttributeValues": expr_vals,
            **({"ExpressionAttributeNames": expr_names} if expr_names else {}),
        }

    # ——— Update User ———
    USERS_TABLE.update_item(Key={"userID": user_id}, **build_update_params(update_fields))

    # ——— Sync Email into Employees ———
    if "officialEmail" in body:
        EMPLOYEES_TABLE.update_item(
            Key={"employeeID": user_id},
            UpdateExpression="SET officialEmail = :email, updatedAt = :now, updatedBy = :by",
            ExpressionAttributeValues={
                ":email": body["officialEmail"].lower().strip(),
                ":now": now_iso,
                ":by": caller_id,
            },
        )

    # ——— Response ———
    return build_response(
        event,
        data={"message": "User record updated successfully"},
        status=200,
    )

















# ——— Delete User(s) API ———
def handle_delete_user(event, caller_id: str):
    """
    Delete user(s).

    Rules:
    - Requires Users.view and Users.delete permissions
    - Enforces self, selected, owner, all (policy engine rules)
    - Removes from Users table
    - Disables login in Employees table
    - Deletes associated grants from UserGrants table
    - Decrements rolecount in roles_t table using (rid, role) from Users table
    """

    # ——— Input Validation ———
    body = json.loads(event.get("body") or "{}")
    user_ids = body.get("userIDs")

    if not user_ids or not isinstance(user_ids, list):
        return build_response(
            event,
            error="Validation error",
            data={"userIDs": "Must be a non-empty list of user IDs"},
            status=400
        )

    # Prevent self-deletion
    if caller_id in user_ids:
        return build_response(
            event,
            error="Forbidden: you cannot delete your own account.",
            status=403
        )

    deleted = 0

    # ——— Process Each User ———
    for uid in user_ids:
        # Fetch user record
        user_item = USERS_TABLE.get_item(Key={"userID": uid}).get("Item")
        if not user_item:
            return build_response(
                event,
                status=404,
                error=f"User with ID {uid} not found"
            )

        # ——— Access Control Enforcement ———
        # Check view permission
        deny = decision_or_deny(
            event,
            caller_id,
            "Users",
            "view",
            record_id=uid,
            record_type="user",
            resource_object=user_item
        )
        if deny:
            return deny

        # Check delete permission
        deny = decision_or_deny(
            event,
            caller_id,
            "Users",
            "delete",
            record_id=uid,
            record_type="user",
            resource_object=user_item
        )
        if deny:
            return deny

        try:
            # ——— Delete from Users Table ———
            USERS_TABLE.delete_item(Key={"userID": uid})

            # ——— Disable login in Employees Table ———
            EMPLOYEES_TABLE.update_item(
                Key={"employeeID": uid},
                UpdateExpression="SET loginEnabled = :false, updatedAt = :now, updatedBy = :by",
                ExpressionAttributeValues={
                    ":false": False,
                    ":now": datetime.utcnow().isoformat(),
                    ":by": caller_id
                }
            )

            # ——— Remove Grants from UserGrants Table ———
            grants = USER_GRANTS_TABLE.query(
                KeyConditionExpression=Key("userID").eq(uid)
            ).get("Items", [])

            with USER_GRANTS_TABLE.batch_writer() as batch:
                for g in grants:
                    batch.delete_item(Key={"userID": uid, "ovID": g["ovID"]})

            # ——— Decrement Role Count in Roles Table ———
            rids = user_item.get("rids", [])
            roles = user_item.get("roles", [])
            for rid, role in zip(rids, roles):
                try:
                    ROLES_TABLE.update_item(
                        Key={"rid": rid, "role": role},
                        UpdateExpression="SET rolecount = if_not_exists(rolecount, :zero) - :one",
                        ConditionExpression="attribute_exists(rid)",
                        ExpressionAttributeValues={
                            ":one": 1,
                            ":zero": 0
                        }
                    )
                except Exception as e:
                    print(f" Failed to decrement rolecount for {rid}/{role}: {e}")

            deleted += 1

        except Exception as e:
            return build_response(
                event,
                status=500,
                error=f"Deletion failed for {uid}: {str(e)}"
            )

    # ——— Final Response ———
    return build_response(
        event,
        status=200,
        data={"message": f"{deleted} user record(s) deleted successfully."}
    )








# ——— Get Policies For User Function ———
def get_policies_for_user(user_id: str, modules: str | list):
    """
    Fetch and merge role-based + override policies for a user.
    Ensures SelectedIds/SelectedCreators only apply when explicitly allowed.
    Falls back to role-level selections when override doesn’t redefine them.
    """

    valid_view_values = ["all", "self", "selected", "selected_by_creator", "none"]

    # Normalize modules input
    if isinstance(modules, str):
        modules = [m.strip() for m in modules.split(",") if m.strip()]
    if not isinstance(modules, list) or not modules:
        return {"error": "Modules must be a non-empty string or list", "status": 400}

    # Fetch user record (roles)
    user_record = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if not user_record or not user_record.get("roles"):
        return {"error": "User has no roles assigned", "status": 403}

    assigned_roles = user_record["roles"]

    # Containers
    module_policies     = {}   # requested modules only
    all_modules_merged  = {}   # all policies merged (roles + overrides)
    general_policies    = {}   # cross-module policies

    # Load role policies
    for role_name in assigned_roles:
        role_query = ROLES_TABLE.query(
            IndexName=ROLE_BY_NAME_INDEX,
            KeyConditionExpression=Key("role").eq(role_name),
        ).get("Items", [])

        if not role_query:
            continue

        role_record   = role_query[0]
        role_policies = role_record.get("Policies", {}) or {}

        # Convert JSON string → dict if needed
        if isinstance(role_policies, str):
            try:
                role_policies = json.loads(role_policies)
            except Exception:
                role_policies = {}

        # Store baseline policies
        for mod_name, mod_conf in role_policies.items():
            all_modules_merged.setdefault(mod_name, mod_conf)

        # Track requested modules
        for module in modules:
            if module in role_policies:
                module_policies[module] = role_policies[module]

        # Collect general (cross-cutting) policies
        if "General" in role_policies:
            general_policies.update(role_policies["General"].get("allow", {}))

    # Fetch overrides
    try:
        resp = USER_GRANTS_TABLE.query(
            KeyConditionExpression=Key("userID").eq(user_id) & Key("ovID").begins_with("B#OVR#")
        )
        override_items = resp.get("Items", []) or []
    except Exception as e:
        print("Error fetching overrides:", e)
        override_items = []

    # Deduplicate: keep only latest override per module
    latest_override_per_module = {}
    for ovr in override_items:
        if str(ovr.get("Status", "")).lower() != "active":
            continue

        mod_name = ovr.get("module")
        if not mod_name:
            continue

        updated_at = ovr.get("updatedAt") or ovr.get("createdAt")
        if updated_at:
            updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
        else:
            updated_at = datetime.min

        if (mod_name not in latest_override_per_module or
                updated_at > latest_override_per_module[mod_name][1]):
            latest_override_per_module[mod_name] = (ovr, updated_at)

    override_items = [v[0] for v in latest_override_per_module.values()]

    # Apply overrides (merge with baseline, with fallback)
    for override in override_items:
        mod_name = override.get("module")
        if not mod_name:
            continue

        # Start from baseline (role policies)
        baseline    = all_modules_merged.get(mod_name, {"allow": {}, "deny": {}})
        base_allow  = baseline.get("allow", {}).copy()
        base_deny   = baseline.get("deny", {}).copy()
        base_ids    = baseline.get("SelectedIds", {}).copy()
        base_creators = baseline.get("SelectedCreators", {}).copy()

        merged_allow = base_allow.copy()
        merged_deny  = base_deny.copy()

        # Override allow/deny values
        for action, val in (override.get("Allow") or {}).items():
            merged_allow[action] = val
        for action, val in (override.get("Deny") or {}).items():
            merged_deny[action] = val

        merged = {"allow": merged_allow}
        if merged_deny:
            merged["deny"] = merged_deny

        cleaned_ids, cleaned_creators = {}, {}

        for action, val in merged_allow.items():
            # --- selected ---
            if (
                (isinstance(val, str) and val == "selected") or
                (isinstance(val, list) and "selected" in val)
            ):
                if "SelectedIds" in override:
                    cleaned_ids[action] = override["SelectedIds"].get(action, {})
                elif action in base_ids:  # 🔙 fallback to role
                    cleaned_ids[action] = base_ids[action]

            # --- selected_by_creator ---
            if (
                (isinstance(val, str) and val == "selected_by_creator") or
                (isinstance(val, list) and "selected_by_creator" in val)
            ):
                if "SelectedCreators" in override:
                    cleaned_creators[action] = override["SelectedCreators"].get(action, {})
                elif action in base_creators:  # 🔙 fallback to role
                    cleaned_creators[action] = base_creators[action]

        if cleaned_ids:
            merged["SelectedIds"] = cleaned_ids
        elif "SelectedIds" in merged:
            del merged["SelectedIds"]

        if cleaned_creators:
            merged["SelectedCreators"] = cleaned_creators
        elif "SelectedCreators" in merged:
            del merged["SelectedCreators"]

        all_modules_merged[mod_name] = merged
        if mod_name in modules:
            module_policies[mod_name] = merged

    # Slim policy helper (extra safety)
    def slim_policy(policy: dict) -> dict:
        if not policy:
            return {"allow": {}}

        slim = {"allow": policy.get("allow", {})}

        # SelectedIds
        if "SelectedIds" in policy:
            for action, val in slim["allow"].items():
                if (
                    (isinstance(val, str) and val == "selected") or
                    (isinstance(val, list) and "selected" in val)
                ):
                    slim.setdefault("SelectedIds", {})[action] = policy["SelectedIds"].get(action, {})

        # SelectedCreators
        if "SelectedCreators" in policy:
            for action, val in slim["allow"].items():
                if (
                    (isinstance(val, str) and val == "selected_by_creator") or
                    (isinstance(val, list) and "selected_by_creator" in val)
                ):
                    slim.setdefault("SelectedCreators", {})[action] = policy["SelectedCreators"].get(action, {})

        return slim

    # Special cases: cross-module inclusions
    if "Clients" in modules or "Contacts" in modules:
        if "Projects" in all_modules_merged:
            module_policies["Projects"] = slim_policy(all_modules_merged["Projects"])
        else:
            module_policies["Projects"] = {"allow": {"view": []}}

    if "Projects" in modules:
        if "ProjectAssignments" in all_modules_merged:
            module_policies["ProjectAssignments"] = slim_policy(all_modules_merged["ProjectAssignments"])
        else:
            module_policies["ProjectAssignments"] = {"allow": {"view": []}}

        if "Tasks" in all_modules_merged:
            module_policies["Tasks"] = slim_policy(all_modules_merged["Tasks"])
        else:
            module_policies["Tasks"] = {"allow": {"view": []}}

    # Build moduleAccess
    module_access = []
    for mod_name, mod_conf in all_modules_merged.items():
        # --- Skip generic TimeEntries check ---
        if mod_name == "TimeEntries":
            continue

        view_conf = mod_conf.get("allow", {}).get("view")

        if not view_conf or view_conf == "none" or view_conf in [{}, []]:
            continue

        if isinstance(view_conf, str) and view_conf in valid_view_values and view_conf != "none":
            module_access.append(mod_name)
        elif isinstance(view_conf, list) and any(v in valid_view_values for v in view_conf if v != "none"):
            module_access.append(mod_name)
        elif isinstance(view_conf, dict) and (
            ("selected" in view_conf and view_conf["selected"]) or
            ("selected_by_creator" in view_conf and view_conf["selected_by_creator"])
        ):
            module_access.append(mod_name)

    # --- Special strict TimeEntries.records_view check ---
    timeentries_conf = all_modules_merged.get("TimeEntries", {})
    if timeentries_conf:
        records_view = timeentries_conf.get("allow", {}).get("records_view")
        if (
            records_view == "all"
            or records_view == "self"
            or records_view == "selected"
            or (isinstance(records_view, list) and any(v in ["all", "self", "selected"] for v in records_view))
        ):
            module_access.append("TimeEntries")

    # Build response
    response = {
        "roles": assigned_roles,
        "Policies": module_policies,
        "general": general_policies,
    }

    if module_access:
        response["moduleAccess"] = sorted(module_access)

    return response






# -------------------- Sign Out Handler --------------------
def handle_signout(event, auth_context):
    """
    Sign out a user by removing refresh token and clearing cookie.
    """
    user_id = auth_context.get("sub")

    # ——— Validate Authentication ———
    if not user_id:
        return build_response(
            event,
            error="Unauthorized",
            data={"message": "Missing authentication"},
            status=401,
        )

    try:
        # ——— Invalidate Refresh Token ———
        USERS_TABLE.update_item(
            Key={"userID": user_id},
            UpdateExpression="REMOVE refreshToken",
        )

        # ——— Clear Cookie ———
        clear_cookie = (
            "refreshToken=; HttpOnly; Secure; Path=/; "
            "SameSite=None; Max-Age=0"
        )

        # ——— Response ———
        return build_response(
            event,
            data={"message": "Signed out successfully"},
            cookies=clear_cookie,
            plain_text=True,
            status=200,
        )

    except Exception as error:
        # ——— Error Response ———
        return build_response(
            event,
            error="Signout failed",
            data={"details": str(error)},
            status=500,
        )




# ——— Update Employee Profile Function ———
def update_employee_profile(event, employee_id: str, body: dict, caller_id: str):

    # Normalize ID (support employeeID or userID from payload)
    target_id = body.get("employeeID") or body.get("userID") or employee_id

    # Fetch employee record
    employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": target_id}).get("Item")
    if not employee_record:
        return build_response(event, error="Employee not found", status=404)

    now_iso = datetime.utcnow().isoformat()
    update_fields, remove_fields = {}, []
    s3_key = f"profiles/{target_id}.png"

    # Profile picture upload/replace
    if raw_b64 := body.get("profileImageBase64"):
        raw = raw_b64.split(",", 1)[1] if raw_b64.startswith("data:") else raw_b64
        raw += "=" * (-len(raw) % 4)  # fix base64 padding

        try:
            img = base64.b64decode(raw)
        except Exception:
            return build_response(event, error="Invalid base64 image", status=400)

        if len(img) > 4 * 1024 * 1024:
            return build_response(event, error="Image too large", status=413)

        # Replace old profile picture in S3
        S3.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        S3.put_object(Bucket=S3_BUCKET_NAME, Key=s3_key, Body=img)

        url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
        update_fields["profilePictureURL"] = url

        # Sync update to Users table
        USERS_TABLE.update_item(
            Key={"userID": target_id},
            UpdateExpression="SET profilePictureURL = :url, updatedAt = :now, updatedBy = :by",
            ExpressionAttributeValues={
                ":url": url,
                ":now": now_iso,
                ":by": caller_id
            }
        )

    # Profile picture removal
    if body.get("removeProfilePicture"):
        S3.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        remove_fields.append("profilePictureURL")

        USERS_TABLE.update_item(
            Key={"userID": target_id},
            UpdateExpression="REMOVE profilePictureURL SET updatedAt = :now, updatedBy = :by",
            ExpressionAttributeValues={
                ":now": now_iso,
                ":by": caller_id
            }
        )

    # Basic fields (firstName, lastName, officialEmail)
    for field in ["firstName", "lastName", "officialEmail"]:
        if field in body:
            update_fields[field] = body[field]

    # Duplicate email check
    if "officialEmail" in update_fields:
        email = update_fields["officialEmail"]

        user_items = USERS_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="userID"
        ).get("Items", [])

        employee_items = EMPLOYEES_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="employeeID"
        ).get("Items", [])

        for rec in (user_items or []) + (employee_items or []):
            existing_id = rec.get("userID") or rec.get("employeeID")
            if existing_id and existing_id != target_id:
                return build_response(
                    event,
                    error="Duplicate officialEmail",
                    data={"officialEmail": "Email already in use"},
                    status=409
                )

        # Sync officialEmail to Users table
        USERS_TABLE.update_item(
            Key={"userID": target_id},
            UpdateExpression="SET officialEmail = :email, updatedAt = :now, updatedBy = :by",
            ExpressionAttributeValues={
                ":email": email,
                ":now": now_iso,
                ":by": caller_id
            }
        )

    # Password set/replace
    if "newPassword" in body:
        plain_password = body["newPassword"]

        if not plain_password or len(plain_password) < 6:
            return build_response(event, error="Password must be at least 6 characters", status=400)

        hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode("utf-8")

        USERS_TABLE.update_item(
            Key={"userID": target_id},
            UpdateExpression="SET passwordHash  = :pwd, updatedAt = :now, updatedBy = :by",
            ExpressionAttributeValues={
                ":pwd": hashed_password,
                ":now": now_iso,
                ":by": caller_id
            }
        )

    # Helper for update expression (Employees table)
    def build_update_params(fields_dict):
        set_clauses, expr_vals = [], {}

        for key, val in fields_dict.items():
            set_clauses.append(f"{key} = :{key}")
            expr_vals[f":{key}"] = val

        clauses = []
        if set_clauses:
            clauses.append("SET " + ", ".join(set_clauses))
        if remove_fields:
            clauses.append("REMOVE " + ", ".join(remove_fields))

        return {
            "UpdateExpression": " ".join(clauses),
            "ExpressionAttributeValues": expr_vals
        }

    # Apply updates to Employees table
    if update_fields or remove_fields:
        EMPLOYEES_TABLE.update_item(
            Key={"employeeID": target_id},
            **build_update_params(update_fields)
        )

    # Success response
    return build_response(
        event,
        data={"message": "Profile updated successfully"},
        status=200
    )




# ——— Get User Profile Function ———
def handleGetUserProfile(event, queried_user_id):
    try:
        # Get employee record
        employee_resp = EMPLOYEES_TABLE.get_item(Key={'employeeID': queried_user_id})
        employee_item = employee_resp.get('Item')
        if not employee_item:
            return build_response(event, error="Employee not found", status=404)

        # Get user record (for profile picture)
        user_resp = USERS_TABLE.get_item(Key={'userID': queried_user_id})
        user_item = user_resp.get('Item', {})

        # Build user object
        users = {
            'userID':            queried_user_id,
            'firstName':         employee_item.get('firstName') or employee_item.get('firstname'),
            'lastName':          employee_item.get('lastName')  or employee_item.get('lastname'),
            'email':             employee_item.get('officialEmail') or employee_item.get('email'),
            'profilePictureURL': user_item.get('profilePictureURL')
        }

        # Return raw (lambda_handler will add CORS headers)
        return {
            'statusCode': 200,
            'body': json.dumps({'users': users})
        }

    except Exception as e:
        return build_response(event, error=str(e), status=500)
