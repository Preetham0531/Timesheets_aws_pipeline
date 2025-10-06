import uuid
import json
from datetime import datetime
from boto3.dynamodb.conditions import Attr, Key

from utils import *


# ----------------------------
# Submit Backtrack Request
# ---------------------------
def handle_backtrack_request(event, auth):
    """
    Handles the submission of one or more backtrack requests from users.  
    Validates input, checks user and project permissions,
    ensures no duplicate or conflicting requests, 
    persists valid requests, and notifies eligible approvers via email.

    Args:
        event (dict): Lambda-style event payload containing request information.
        auth (dict): Auth info (not currently used directly).

    Returns:
        dict: API response formatted by build_response().
    """

    # Parse body (accept string or dict)
    raw_body = event.get("body", {})
    if isinstance(raw_body, str):
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            return build_response(
                error="Invalid JSON in request body",
                status=400,
                event=event
            )
    elif isinstance(raw_body, dict):
        body = raw_body
    else:
        return build_response(
            error="Invalid request body type",
            status=400,
            event=event
        )

    # Extract and validate userID
    user_id = body.get("userID")
    if not user_id:
        return build_response(
            error="Validation error",
            fields={"userID": "Missing userID in request body"},
            status=400,
            event=event
        )

    # Ensure user exists
    user_item = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
    if not user_item:
        return build_response(
            error="Validation error",
            fields={"userID": "User not found"},
            status=404,
            event=event
        )
    full_name = " ".join(filter(None, [
        user_item.get("firstName"),
        user_item.get("lastName")
    ])) or user_id

    # Validate entries array
    entries = body.get("entries", [])
    if not isinstance(entries, list) or not entries:
        return build_response(
            error="Validation error",
            fields={"entries": "Must be a non-empty list"},
            status=400,
            event=event
        )

    created_requests = []
    conflicts = []

    for entry in entries:
        project_id = entry.get("projectID")
        entry_dates = entry.get("entryDates")

        # Validate projectID and entryDates
        if not project_id:
            conflicts.append({"projectID": None, "error": "Missing projectID"})
            continue
        if not isinstance(entry_dates, list) or not entry_dates:
            conflicts.append({"projectID": project_id, "error": "Invalid entryDates"})
            continue

        # Verify project exists
        project_item = PROJECTS_TABLE.get_item(Key={"projectID": project_id}).get("Item")
        if not project_item:
            conflicts.append({"projectID": project_id, "error": "Project not found"})
            continue

        # Check user assignment to the project
        assign_resp = ASSIGNMENTS_TABLE.query(
            IndexName="ProjectAssignments-index",
            KeyConditionExpression=(
                Key("projectID").eq(project_id) &
                Key("userID").eq(user_id)
            )
        )
        if not assign_resp.get("Items"):
            conflicts.append({"projectID": project_id, "error": "User not assigned to project"})
            continue

        # Check for existing Pending/Approved backtracks for these dates
        existing_resp = BACKTRACK_TABLE.query(
            IndexName="UserProjectIndex",
            KeyConditionExpression=(
                Key("userID").eq(user_id) &
                Key("projectID").eq(project_id)
            ),
            FilterExpression=Attr("approvalStatus").is_in(["Pending", "Approved"])
        )
        existing_dates = {
            d
            for item in existing_resp.get("Items", [])
            for d in item.get("entryDates", [])
        }
        dupes = [d for d in entry_dates if d in existing_dates]
        if dupes:
            conflicts.append({
                "projectID": project_id,
                "duplicateDates": sorted(dupes)
            })
            continue

        # Generate request ID
        request_id = str(uuid.uuid4())

        # Compose notification email
        project_name = project_item.get("projectName", "Unknown Project")
        subject = f"Backtrack Request from {full_name}"
        text = (
            f"{full_name} requested backtrack on "
            f"{', '.join(entry_dates)} for {project_name}."
        )
        html = build_html_email(subject, {
            "User": full_name,
            "Project": project_name,
            "Requested Dates": ", ".join(entry_dates)
        })

        # Notify eligible approvers for this project
        approver_resp = ASSIGNMENTS_TABLE.query(
            IndexName="ProjectAssignments-index",
            KeyConditionExpression=Key("projectID").eq(project_id)
        )
        for approver in approver_resp.get("Items", []):
            approver_id = approver.get("userID")
            if approver_id == user_id:
                continue

            # Lookup privileges
            rp_item = ROLE_PRIVILEGES_TABLE.get_item(Key={"userID": approver_id}).get("Item")
            if not rp_item or "037" not in rp_item.get("privileges", []):
                continue

            # Send email if approver has a valid email address
            approver_user = USERS_TABLE.get_item(Key={"userID": approver_id}).get("Item", {})
            approver_email = approver_user.get("email")
            if approver_email:
                send_email(approver_email, subject, text, html)

        # Persist the backtrack request after sending emails
        BACKTRACK_TABLE.put_item(Item={
            "requestID":      request_id,
            "userID":         user_id,
            "projectID":      project_id,
            "entryDates":     entry_dates,
            "approvalStatus": "Pending",
            "requestedAt":    datetime.utcnow().isoformat(),
        })
        created_requests.append({
            "projectID":  project_id,
            "requestID":  request_id
        })

    # If none created and we have conflicts, return 409
    if not created_requests and conflicts:
        return build_response(
            error="All requests failed due to validation or duplication.",
            fields={"conflicts": conflicts},
            status=409,
            event=event
        )

    # Return success payload
    return build_response(
        data={
            "message":   f"{len(created_requests)} backtrack request(s) created.",
            "requests":  created_requests,
            "conflicts": conflicts or None
        },
        event=event
    )





# ----------------------------
# Approve Backtrack Request
# ----------------------------
def handle_backtrack_approval(event, auth):
    """
    Approves or rejects a backtrack request based on approver's privileges and assignment.

    Validates the request, checks approver permissions, updates the request status,
    and sends an email notification to the requester.

    Args:
        event (dict): Incoming Lambda event or API event, containing the request info.
        auth (dict): Auth information for the requester (should include user_id, role, email).

    Returns:
        dict: Response generated via build_response().
    """

    # Parse and validate the request body (accepts string or dict)
    try:
        raw_body = event.get("body", {})
        if isinstance(raw_body, str):
            body = json.loads(raw_body)
        elif isinstance(raw_body, dict):
            body = raw_body
        else:
            return build_response(error="Invalid request body type", status=400, event=event)
    except Exception:
        return build_response(error="Invalid JSON in request body", status=400, event=event)

    request_id = body.get("requestID")
    approval_status = body.get("approvalStatus")

    # Validate approval status
    if approval_status not in ["Approved", "Rejected"]:
        return build_response(error="approvalStatus must be 'Approved' or 'Rejected'", status=400, event=event)

    # Fetch the backtrack request
    request = BACKTRACK_TABLE.get_item(Key={"requestID": request_id}).get("Item")
    if not request:
        return build_response(error="Backtrack request not found", status=404, event=event)

    approver_id = auth.get("user_id")
    approver_role = auth.get("role", "").lower()

    # Check if the user is authorized to approve/reject
    if approver_role not in ["admin", "super admin"]:
        privilege_item = ROLE_PRIVILEGES_TABLE.get_item(Key={"userID": approver_id}).get("Item")
        if not privilege_item or "037" not in privilege_item.get("privileges", []):
            return build_response(error="Forbidden: Missing privilege 037", status=403, event=event)
        # Check if the user is assigned to the same project
        assigned = ASSIGNMENTS_TABLE.query(
            IndexName="projectID-userID-index",
            KeyConditionExpression=Key("projectID").eq(request["projectID"]) & Key("userID").eq(approver_id)
        ).get("Items", [])
        if not assigned:
            return build_response(error="Forbidden: Not assigned to project", status=403, event=event)

    # Update the request approval status
    BACKTRACK_TABLE.update_item(
        Key={"requestID": request_id},
        UpdateExpression="SET #s = :s, reviewedAt = :r",
        ExpressionAttributeNames={"#s": "approvalStatus"},
        ExpressionAttributeValues={
            ":s": approval_status,
            ":r": datetime.utcnow().isoformat()
        }
    )

    # Notify the requester by email
    user = USERS_TABLE.get_item(Key={"userID": request["userID"]}).get("Item", {})
    subject = f"Backtrack Request {approval_status}"
    text = (
        f"Hello {user.get('firstName', '')},\n\n"
        f"Your backtrack request for {', '.join(request['entryDates'])} "
        f"has been {approval_status}."
    )
    html = build_html_email(subject, {
        "Status": approval_status,
        "Backtrack Dates": ", ".join(request["entryDates"]),
        "Reviewed By": auth.get("email", "")
    })
    if user.get("email"):
        send_email(user["email"], subject, text, html)

    return build_response(data={"message": f"Request {approval_status}"}, event=event)
