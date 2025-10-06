
import base64
import json
import os
import uuid
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set



# Third-party libraries
import bcrypt
import boto3
import jwt
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from email_utils import *
from utils import *
from utils import decision_or_deny
from policy_engine import evaluate, AccessRequest


S3 = boto3.client("s3")
RESET_LINK_BASE_URL = "https://timesheets.dev.inferai.ai"


# ——— Create Employee Function ———
def handle_Create_Employee(event, body, auth_context, caller_id: str):

    # Normalize input
    requester_id = auth_context.get("sub") or auth_context.get("user_id")

    # Validate required fields
    required_fields = ("firstName", "officialEmail")
    missing_fields = [f for f in required_fields if not body.get(f)]
    if missing_fields:
        return build_response(
            event,
            status=400,
            data={"error": f"Missing fields: {', '.join(missing_fields)}"}
        )

    # Duplicate email check
    try:
        existing_employee = EMPLOYEES_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(body["officialEmail"])
        )
        if existing_employee.get("Items"):
            return build_response(
                event,
                status=400,
                data={"error": "An employee with this email already exists"}
            )
    except Exception as e:
        return build_response(
            event,
            status=500,
            data={"error": f"Duplicate check failed: {str(e)}"}
        )

    # Generate IDs
    try:
        employee_id = str(uuid.uuid4())
        display_id = generate_unique_display_id("EMP")
    except Exception as e:
        return build_response(
            event,
            status=500,
            data={"error": f"ID generation failed: {str(e)}"}
        )

    created_at = datetime.utcnow().isoformat()

    # Build employee record
    employee_fields = [
        "firstName", "middleName", "lastName", "officialEmail", "secondaryEmail",
        "mobileNumber", "phoneNumber", "street1", "street2", "city", "state",
        "zipCode", "country", "designation", "department", "company",
        "category", "labourCategory"
    ]

    employee_item = {
        "employeeID": employee_id,
        "displayID": display_id,
        "createdAt": created_at,
        "createdBy": requester_id,
        "loginEnabled": False,
        "status": body.get("status", "Active"),
        **{field: body.get(field) for field in employee_fields if body.get(field) is not None}
    }

    # Privacy handling
    privacy = body.get("privacy", "public").lower()
    allowed_users = body.get("allowedUsers") or []

    if privacy == "private":
        # Always include creator
        allowed_users.append(requester_id)
        # Deduplicate
        allowed_users = list(set(allowed_users))

        employee_item["privacy"] = "private"
        employee_item["allowedUsers"] = allowed_users
    else:
        employee_item["privacy"] = "public"
        # don’t save allowedUsers for public employees

    # Policy check: Employees.create
    deny = decision_or_deny(
        event,
        caller_id,
        "Employees",
        "create",
        record_id=employee_id,
        record_type="employee",
        resource_object=employee_item,
        extra_context={"ownerUserId": caller_id}
    )
    if deny:
        return deny

    # Save employee record
    try:
        EMPLOYEES_TABLE.put_item(Item=employee_item)
    except Exception as e:
        return build_response(
            event,
            status=500,
            data={"error": f"Failed to save employee: {str(e)}"}
        )

    # Success response
    return build_response(
        event,
        status=200,
        data={
            "message": "Employee created successfully",
            "employeeID": employee_id,
            "displayID": display_id
        }
    )








# ——— Get Employees Function ———
def handleGetEmployees(event, caller_id: str):

    # Parse query parameters
    query_params = event.get("queryStringParameters") or {}
    view_type    = (query_params.get("view") or "").strip().lower()
    employee_id  = query_params.get("employeeID")

    # ——— Case: Single Employee ———
    if employee_id:
        resp   = EMPLOYEES_TABLE.get_item(Key={"employeeID": employee_id})
        record = resp.get("Item")

        if not record:
            return build_response(event, error="Employee not found", status=404)

        # Policy check (highest priority)
        deny = decision_or_deny(
            event,
            caller_id,
            "Employees",
            "view",
            record_id=employee_id,
            record_type="employee",
            resource_object=record,
        )
        print("deny policy->>>>",deny)
        if deny:
            return deny

        # Privacy check (only if private)
        if record.get("privacy") == "private":
            allowed = record.get("allowedUsers", [])
            if caller_id not in allowed:
                return build_response(event, error="Forbidden: private employee", status=403)

        # Enrich with creator/updater names
        if record.get("createdBy"):
            record["createdByName"] = get_user_full_name(record["createdBy"])
        if record.get("updatedBy"):
            record["updatedByName"] = get_user_full_name(record["updatedBy"])

        return build_response(
            event,
            data={"employee": record, "status": 200},
        )

    # ——— Case: List Employees ———
    scan_args = {"Limit": 150}

    # Pagination
    if last_key := query_params.get("lastKey"):
        scan_args["ExclusiveStartKey"] = {"employeeID": last_key}

    # Special view filter: non-login users
    if view_type == "nonloginusers":
        scan_args["FilterExpression"] = Attr("loginEnabled").ne(True)

    scan_response   = EMPLOYEES_TABLE.scan(**scan_args)
    records         = scan_response.get("Items", []) or []
    last_key_value  = scan_response.get("LastEvaluatedKey", {}).get("employeeID")

    filtered_records = []
    for record in records:
        r_id = record.get("employeeID")

        # Policy check
        deny = decision_or_deny(
            event,
            caller_id,
            "Employees",
            "view",
            record_id=r_id,
            record_type="employee",
            resource_object=record,
        )
        if deny:
            continue

        # Privacy check
        if record.get("privacy") == "private":
            allowed = record.get("allowedUsers", [])
            if caller_id not in allowed:
                continue

        # Enrich with creator/updater names
        if record.get("createdBy"):
            record["createdByName"] = get_user_full_name(record["createdBy"])
        if record.get("updatedBy"):
            record["updatedByName"] = get_user_full_name(record["updatedBy"])

        filtered_records.append(record)

    return build_response(
        event,
        data={
            "employees" if view_type != "nonloginusers" else "nonLoginUsers": filtered_records,
            "total": len(filtered_records),
            "lastKey": last_key_value,
            "status": 200,
        },
    )














# ——— Update Employee Record ———
def update_employee_record(event, employee_id: str, body: dict, caller_id: str):

    # Fetch employee record for policy enforcement
    employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": employee_id}).get("Item")
    if not employee_record:
        return build_response(event, error="Employee not found", status=404)

    # Policy check: Employees.view
    deny = decision_or_deny(
        event,
        caller_id,
        "Employees",
        "view",
        record_id=employee_id,
        record_type="employee",
        resource_object=employee_record,
        extra_context={"ownerUserId": employee_id}
    )
    if deny:
        return deny

    # Policy check: Employees.modify
    deny = decision_or_deny(
        event,
        caller_id,
        "Employees",
        "modify",
        record_id=employee_id,
        record_type="employee",
        resource_object=employee_record,
        extra_context={"ownerUserId": employee_id}
    )
    if deny:
        return deny

    # Privacy enforcement
    if employee_record.get("privacy") == "private":
        allowed = employee_record.get("allowedUsers", [])
        if caller_id not in allowed:
            return build_response(
                event,
                error="Forbidden: You are not allowed to modify this private employee",
                status=403
            )

    now_iso = datetime.utcnow().isoformat()

    # Allowed updatable fields
    allowed_fields = [
        "firstName", "middleName", "lastName",
        "officialEmail", "secondaryEmail",
        "mobileNumber", "phoneNumber",
        "street1", "street2", "city", "state", "zipCode", "country",
        "designation", "department",
        "company", "category",
        "status", "labourCategory",
        "privacy", "allowedUsers"
    ]
    update_fields = {k: body[k] for k in allowed_fields if k in body}
    update_fields.update({"updatedAt": now_iso, "updatedBy": caller_id})

    remove_fields = []

    # Duplicate officialEmail check
    if "officialEmail" in body:
        email = body["officialEmail"]

        # Users table check
        user_items = USERS_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="userID"
        ).get("Items", [])

        # Employees table check
        employee_items = EMPLOYEES_TABLE.query(
            IndexName="GSI_Email",
            KeyConditionExpression=Key("officialEmail").eq(email),
            ProjectionExpression="employeeID"
        ).get("Items", [])

        for rec in (user_items or []) + (employee_items or []):
            existing_id = rec.get("userID") or rec.get("employeeID")
            if existing_id and existing_id != employee_id:
                return build_response(
                    event,
                    error="Duplicate officialEmail",
                    data={"officialEmail": "Email already in use"},
                    status=409
                )

        # Sync to Users if loginEnabled
        user_item = USERS_TABLE.get_item(Key={"userID": employee_id}).get("Item")
        if user_item and user_item.get("loginEnabled"):
            USERS_TABLE.update_item(
                Key={"userID": employee_id},
                UpdateExpression="SET officialEmail = :email, updatedAt = :now, updatedBy = :by",
                ExpressionAttributeValues={
                    ":email": email,
                    ":now": now_iso,
                    ":by": caller_id
                }
            )

    # Privacy update logic
    if "privacy" in update_fields:
        new_privacy = str(update_fields["privacy"]).lower()

        if new_privacy == "private":
            allowed_users = body.get("allowedUsers") or employee_record.get("allowedUsers", [])
            if not allowed_users:
                allowed_users = [caller_id]
            if caller_id not in allowed_users:
                allowed_users.append(caller_id)

            update_fields["privacy"] = "private"
            update_fields["allowedUsers"] = allowed_users
        else:
            update_fields["privacy"] = "public"
            remove_fields.append("allowedUsers")

    elif "allowedUsers" in update_fields:
        if employee_record.get("privacy") == "private":
            allowed_users = body.get("allowedUsers", [])
            if not allowed_users:
                allowed_users = [caller_id]
            if caller_id not in allowed_users:
                allowed_users.append(caller_id)

            update_fields["allowedUsers"] = allowed_users
        else:
            update_fields.pop("allowedUsers", None)

    # Build DynamoDB update expression
    def build_update_params(fields_dict):
        RESERVED = {"status", "state"}
        set_clauses, expr_vals, expr_names = [], {}, {}

        for key, val in fields_dict.items():
            placeholder = f"#{key}" if key in RESERVED else key
            if key in RESERVED:
                expr_names[placeholder] = key
            set_clauses.append(f"{placeholder} = :{key}")
            expr_vals[f":{key}"] = val

        clauses = []
        if set_clauses:
            clauses.append("SET " + ", ".join(set_clauses))
        if remove_fields:
            clauses.append("REMOVE " + ", ".join(remove_fields))

        return {
            "UpdateExpression": " ".join(clauses),
            "ExpressionAttributeValues": expr_vals,
            **({"ExpressionAttributeNames": expr_names} if expr_names else {})
        }

    # Update employee record
    if update_fields or remove_fields:
        EMPLOYEES_TABLE.update_item(
            Key={"employeeID": employee_id},
            **build_update_params(update_fields)
        )

    return build_response(
        event,
        data={"message": "Employee record updated successfully"},
        status=200
    )






# ——— Delete Employee ———
def handle_delete_employee(event, caller_id: str):
    body = json.loads(event.get("body") or "{}")
    employee_ids = body.get("employeeIDs")

    # Validate input
    if not employee_ids or not isinstance(employee_ids, list):
        return build_response(
            event,
            error="Validation error",
            data={"employeeIDs": "Must be a non-empty list of employee IDs"},
            status=400
        )

    # Prevent self-deletion
    if caller_id in employee_ids:
        return build_response(
            event,
            error="Forbidden: you cannot delete your own profile.",
            status=403
        )

    deleted, blocked = 0, []

    for emp_id in employee_ids:
        emp_item = EMPLOYEES_TABLE.get_item(Key={"employeeID": emp_id}).get("Item")
        if not emp_item:
            return build_response(
                event,
                error=f"Employee {emp_id} not found",
                status=404
            )

        # Policy check: Employees.view
        deny_view = decision_or_deny(
            event,
            caller_id,
            "Employees",
            "view",
            record_id=emp_id,
            record_type="employee",
            resource_object=emp_item
        )
        if deny_view:
            return deny_view

        # Policy check: Employees.delete
        deny_delete = decision_or_deny(
            event,
            caller_id,
            "Employees",
            "delete",
            record_id=emp_id,
            record_type="employee",
            resource_object=emp_item
        )
        if deny_delete:
            return deny_delete

        # Privacy check (block if private and caller not allowed)
        if emp_item.get("privacy") == "private":
            allowed = emp_item.get("allowedUsers", [])
            if caller_id not in allowed:
                return build_response(
                    event,
                    error=f"Forbidden: employee {emp_id} is private",
                    status=403
                )

        # Block deletion if loginEnabled
        if emp_item.get("loginEnabled"):
            blocked.append(emp_id)
            continue

        # Delete employee record
        EMPLOYEES_TABLE.delete_item(Key={"employeeID": emp_id})
        deleted += 1

    # Return blocked if any loginEnabled employees found
    if blocked:
        return build_response(
            event,
            error="Cannot delete employees with login enabled. Delete user first, then employee.",
            data={"blockedEmployeeIDs": blocked},
            status=409
        )

    return build_response(
        event,
        status=200,
        data={"message": f"{deleted} employee record(s) deleted successfully."})

