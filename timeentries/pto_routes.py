# --------------------------------------------
# PTO Management Routes
# Version: 1.2.0
# Updated: May 17, 2025
# Author: Sainathreddy
# Description: Handles PTO requests, approvals, logs, and email alerts
# --------------------------------------------

import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Attr
from utils import *

# ----------------------------
# Endpoint: Submit PTO request
# ----------------------------
def handle_pto_request(event, auth):
    from utils import get_cors_headers  # Ensure this is in your utils.py

    headers = get_cors_headers(event)
    body = event.get("body", "{}")
    try:
        body = json.loads(body)
    except Exception:
        return build_response(
            error="Invalid JSON in request body",
            status=400,
            event=event
        )

    user_id = auth["user_id"]
    user_email = auth["email"]
    role = auth["role"].lower()

    if role != "user":
        return build_response(
            error="Only users can submit PTO requests.",
            status=403,
            event=event
        )

    user = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item", {})
    full_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip()

    project_id = body.get("projectID", "").strip()
    pto_dates = body.get("ptoDates", [])
    reason = body.get("reason", "").strip()

    if not pto_dates or not isinstance(pto_dates, list):
        return build_response(
            error="Validation error",
            fields={"ptoDates": "Must be a non-empty list"},
            event=event
        )

    project_name = "Internal PTO"
    client_id = "internal"
    company_name = "Internal"
    primary_manager_id = None

    if project_id:
        assignment = ASSIGNMENTS_TABLE.scan(
            FilterExpression=Attr("projectID").eq(project_id) & Attr("userID").eq(user_id)
        ).get("Items", [])
        if not assignment:
            return build_response(
                error="You are not assigned to this project.",
                status=403,
                event=event
            )

        project, err = get_project(project_id)
        if err:
            return build_response(error="Project not found", event=event)
        project_name = project.get("projectName", "Unnamed Project")
        client_id = project.get("clientID", "unknown-client")
        company_name = get_client_name(client_id)
        primary_manager_id = assignment[0].get("primaryManagerID")

    # ---------------- Duplicate PTO check ----------------
    existing_requests = PTO_TABLE.scan(
        FilterExpression=Attr("userID").eq(user_id) &
                         Attr("approvalStatus").is_in(["Pending", "Approved"])
    ).get("Items", [])

    duplicate_dates = {
        date for req in existing_requests for date in req.get("ptoDates", [])
        if date in pto_dates
    }

    if duplicate_dates:
        return build_response(
            error="Duplicate request",
            message="A PTO request already exists for some of these dates.",
            fields={"duplicateDates": sorted(duplicate_dates)},
            status=409,
            event=event
        )

    # ---------------- Conflict check: already logged work ----------------
    conflicting_dates = []
    for d in pto_dates:
        logged_entries = ENTRIES_TABLE.scan(
            FilterExpression=Attr("UserID").eq(user_id) &
                             Attr("Date").eq(d) &
                             Attr("EntryType").eq("daily") &
                             Attr("isPTO").ne(True)
        ).get("Items", [])
        if logged_entries:
            conflicting_dates.append(d)

    if conflicting_dates:
        return build_response(
            error="PTO conflict",
            message="You have already logged work on the requested PTO dates.",
            fields={"conflictingDates": sorted(conflicting_dates)},
            status=409,
            event=event
        )

    # ---------------- Insert PTO Request ----------------
    request_id = str(uuid.uuid4())
    PTO_TABLE.put_item(Item={
        "requestID": request_id,
        "userID": user_id,
        "projectID": project_id or "internal-pto",
        "ptoDates": pto_dates,
        "reason": reason,
        "approvalStatus": "Pending",
        "primaryManagerID": primary_manager_id,
        "createdAt": datetime.utcnow().isoformat()
    })

    if primary_manager_id:
        manager = USERS_TABLE.get_item(Key={"userID": primary_manager_id}).get("Item", {})
        manager_email = manager.get("email")
        if manager_email:
            subject = f"PTO Request from {full_name}"
            text = f"{full_name} requested PTO for {', '.join(pto_dates)}. Reason: {reason}"
            html = build_html_email(subject, {
                "Requested By": full_name,
                "PTO Dates": ", ".join(pto_dates),
                "Reason": reason,
                "Project Name": project_name
            })
            send_email(manager_email, subject, text, html)

    return build_response(
        data={"message": "PTO request submitted", "requestID": request_id},
        event=event
    )



# ----------------------------
# Endpoint: Approve/Reject PTO
# ----------------------------
def handle_pto_approval(event, auth):
    from utils import get_cors_headers  # Ensure it's in utils

    headers = get_cors_headers(event)
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        return build_response(
            error="Invalid JSON in request body",
            status=400,
            event=event
        )

    request_id = body.get("requestID")
    approval_status = body.get("approvalStatus")
    approved_dates = body.get("approvedDates", [])
    manager_comment = body.get("managerComment", "")

    if approval_status not in ["Approved", "Rejected"]:
        return build_response(
            error="approvalStatus must be 'Approved' or 'Rejected'",
            status=400,
            event=event
        )

    # Get the PTO request
    pto_request = PTO_TABLE.get_item(Key={"requestID": request_id}).get("Item")
    if not pto_request:
        return build_response(
            error="PTO request not found",
            status=404,
            event=event
        )

    role = auth["role"].lower()
    approver_id = auth["user_id"]
    if role not in ["admin", "manager"] or (role == "manager" and approver_id != pto_request.get("primaryManagerID")):
        return build_response(
            error="Forbidden: You are not authorized to approve this PTO",
            status=403,
            event=event
        )

    # Validate approved dates
    if approval_status == "Approved":
        original_dates = set(pto_request.get("ptoDates", []))
        invalid_dates = [d for d in approved_dates if d not in original_dates]

        if invalid_dates:
            return build_response(
                error="Invalid approval dates",
                message="Approved dates must be within originally requested PTO dates.",
                fields={"invalidDates": invalid_dates},
                status=400,
                event=event
            )

        if not approved_dates:
            return build_response(
                error="Must provide approvedDates for approval.",
                status=400,
                event=event
            )

    # Update PTO request
    PTO_TABLE.update_item(
        Key={"requestID": request_id},
        UpdateExpression="SET approvalStatus = :s, reviewedAt = :r, reviewedBy = :rb, managerComment = :c, approvedDates = :ad",
        ExpressionAttributeValues={
            ":s": approval_status,
            ":r": datetime.utcnow().isoformat(),
            ":rb": approver_id,
            ":c": manager_comment,
            ":ad": approved_dates
        }
    )

    # Log entries if approved
    if approval_status == "Approved":
        log_pto_entries(
            user_id=pto_request["userID"],
            manager_id=pto_request.get("primaryManagerID"),
            pto_dates=approved_dates,
            project_id=pto_request.get("projectID"),
            notes=pto_request.get("reason", "")
        )

    # Notify user
    user = USERS_TABLE.get_item(Key={"userID": pto_request["userID"]}).get("Item")
    user_email = user.get("email") if user else None

    if user_email:
        subject = f"PTO Request {approval_status}"
        html = build_html_email(subject, {
            "Status": approval_status,
            "Approved Dates": ", ".join(approved_dates),
            "Reviewed By": get_user_name(approver_id),
            "Manager Comment": manager_comment or "-"
        })
        send_email(user_email, subject, subject, html)

    return build_response(
        data={"message": f"PTO request {approval_status}", "requestID": request_id},
        event=event
    )


# ----------------------------
# Utility: Check if date is approved PTO
# ----------------------------
def is_on_approved_pto(user_id, date_to_check):
    result = PTO_TABLE.scan(
        FilterExpression=Attr("userID").eq(user_id) &
                         Attr("approvalStatus").eq("Approved") &
                         Attr("ptoDates").contains(date_to_check)
    )
    return bool(result.get("Items", []))


# ----------------------------
# Utility: Log automatic PTO entries into ENTRIES_TABLE
# ----------------------------
def log_pto_entries(user_id, manager_id, pto_dates, project_id, notes="PTO"):
    now = datetime.utcnow().isoformat()
    user = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    user_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or user_id

    project_name = "Internal PTO"
    client_id = "internal"
    company_name = "Internal"

    if project_id and project_id != "internal-pto":
        project, _ = get_project(project_id)
        if project:
            project_name = project.get("projectName", "Unnamed Project")
            client_id = project.get("clientID", "unknown-client")
            company_name = get_client_name(client_id)

    for date_str in pto_dates:
        entry_id = str(uuid.uuid4())
        ENTRIES_TABLE.put_item(Item={
            "TimeEntryID": entry_id,
            "UserID": user_id,
            "userName": user_name,
            "projectID": project_id or "internal-pto",
            "projectName": project_name,
            "clientID": client_id,
            "companyName": company_name,
            "EntryType": "daily",
            "Date": date_str,
            "TotalHoursWorked": 8,
            "Task": "PTO",
            "Notes": notes or "PTO",
            "status": "Approved",
            "isPTO": True,
            "CreatedAt": now,
            "LastUpdatedAt": now,
            "LastUpdatedBy": user_id,
            "primaryManagerID": manager_id
        })
