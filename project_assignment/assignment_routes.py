import uuid
from datetime import datetime

# Third-party
import boto3
from boto3.dynamodb.conditions import Key, Attr

# AWS DynamoDB client
ddb_client = boto3.client("dynamodb")

# Internal utilities
from utils import *



# ——— Assign Multiple Users to a Project API ———
def handle_assign_multiple_users(
    request_event,
    request_body,
    requesting_user_id
):

    # ——— Extract inputs ———
    project_identifier = request_body.get("projectID")
    assignment_requests = request_body.get("assignments", [])

    # ——— Validate request body ———
    if not project_identifier or not isinstance(assignment_requests, list) or not assignment_requests:
        return build_response(
            error="projectID and assignments are required",
            status=400,
            event=request_event,
        )

    # ——— Verify project exists ———
    project_item = PROJECTS_TABLE.get_item(Key={"projectID": project_identifier}).get("Item")
    if not project_item:
        return build_response(
            error="Project not found",
            status=404,
            event=request_event,
        )

    # ——— Policy check: requester must be able to view project ———
    deny_resp = decision_or_deny(
        request_event,
        requesting_user_id,
        resource="Projects",
        action="view",
        record_id=project_identifier,
        record_type="project",
        resource_object=project_item,
    )
    if deny_resp:
        return deny_resp

    # ——— Policy check: requester must be able to create project assignments ———
    deny_resp = decision_or_deny(
        request_event,
        requesting_user_id,
        resource="ProjectAssignments",
        action="create",
        extra_context={"projectID": project_identifier},
    )
    if deny_resp:
        return deny_resp

    # ——— Fetch existing active assignments ———
    existing_assignments_query = ASSIGNMENTS_TABLE.query(
        IndexName="ProjectAssignments-index",
        KeyConditionExpression=Key("projectID").eq(project_identifier),
        FilterExpression=Attr("status").eq("Active"),
        ProjectionExpression="userID, #role",
        ExpressionAttributeNames={"#role": "role"},
    )

    existing_active_pairs = {
        (item["userID"], item["role"].lower())
        for item in existing_assignments_query.get("Items", [])
    }

    # ——— Validation phase (no DB writes yet) ———
    validated_assignments = []

    for assignment in assignment_requests:
        target_user_id = assignment.get("userID")

        # prevent self-assignment
        if target_user_id == requesting_user_id:
            return build_response(
                error="Forbidden: you cannot assign yourself",
                status=403,
                event=request_event,
            )

        # fetch user record
        user_record = USERS_TABLE.get_item(Key={"userID": target_user_id}).get("Item")
        if not user_record:
            return build_response(
                error=f"User {target_user_id} not found",
                status=404,
                event=request_event,
            )

        # extract role (first one only)
        user_roles = user_record.get("roles", [])
        if not user_roles:
            return build_response(
                error=f"User {target_user_id} has no role assigned",
                status=400,
                event=request_event,
            )

        user_role = str(user_roles[0]).strip().lower()

        # prevent duplicate assignment for same (userID, role)
        if (target_user_id, user_role) in existing_active_pairs:
            return build_response(
                error="User is already assigned",
                status=400,
                event=request_event,
            )

        # store validated assignment
        validated_assignments.append((target_user_id, user_role))

    # ——— Write phase (execute only if validation passed) ———
    current_timestamp_iso = datetime.utcnow().isoformat()

    for target_user_id, user_role in validated_assignments:
        assignment_identifier = str(uuid.uuid4())

        # generate unique display ID
        try:
            assignment_display_identifier = generate_unique_display_id("ASN")
        except Exception as id_error:
            return build_response(
                error=f"ID generation failed: {str(id_error)}",
                status=500,
                event=request_event,
            )

        # insert record into DynamoDB
        ASSIGNMENTS_TABLE.put_item(
            Item={
                "assignmentID": assignment_identifier,
                "displayID": assignment_display_identifier,
                "projectID": project_identifier,
                "userID": target_user_id,
                "role": user_role,
                "assignedBy": requesting_user_id,
                "assignedAt": current_timestamp_iso,
                "status": "Active",
                "createdAt": current_timestamp_iso,
                "updatedAt": current_timestamp_iso,
            }
        )

    # ——— Success response ———
    return build_response(
        data={"message": "Users successfully assigned to project"},
        status=200,
        event=request_event,
    )













# ——— Update Assignment Status Function ———
def handle_update_assignment(request_event, request_body, requesting_user_id):

    # Validate input
    assignment_identifier = request_body.get("assignmentID")
    updated_status = request_body.get("status")
    if not assignment_identifier or not updated_status:
        return build_response(error="assignmentID and status are required", status=400, event=request_event)

    allowed_status_values = {"Active", "Inactive", "Pending", "On Hold"}
    if updated_status not in allowed_status_values:
        return build_response(error="Invalid status value", status=400, event=request_event)

    # Fetch assignment record
    assignment_record = ASSIGNMENTS_TABLE.get_item(Key={"assignmentID": assignment_identifier}).get("Item")
    if not assignment_record:
        return build_response(error="Assignment not found", status=404, event=request_event)

    project_id = assignment_record.get("projectID")

    # Policy check: Projects.view
    deny = decision_or_deny(
        request_event,
        requesting_user_id,
        "Projects",
        "view",
        record_id=project_id,
        record_type="project"
    )
    if deny:
        return deny

    # Policy check: ProjectAssignments.view
    deny = decision_or_deny(
        request_event,
        requesting_user_id,
        "ProjectAssignments",
        "view",
        record_id=assignment_identifier,
        record_type="assignment",
        resource_object=assignment_record
    )
    if deny:
        return deny

    # Policy check: ProjectAssignments.modify
    deny = decision_or_deny(
        request_event,
        requesting_user_id,
        "ProjectAssignments",
        "modify",
        record_id=assignment_identifier,
        record_type="assignment",
        resource_object=assignment_record
    )
    if deny:
        return deny

    # Update assignment status
    try:
        ASSIGNMENTS_TABLE.update_item(
            Key={"assignmentID": assignment_identifier},
            UpdateExpression="SET #status = :status, updatedAt = :updatedAt",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": updated_status,
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except Exception as update_error:
        return build_response(error=f"Failed to update assignment: {update_error}", status=500, event=request_event)

    # Success response
    return build_response(data={"message": "Assignment updated"}, status=200, event=request_event)


# ——— Get Project User Assignments Function ———
def handle_get_project_user_assignments(event, requester_user_id):

    # Extract params
    params = event.get("queryStringParameters") or {}
    project_id = (params.get("projectID") or "").strip()
    if not project_id:
        return build_response(error="projectID is required", status=400, event=event)

    # Parse limit
    try:
        limit = max(1, int(params.get("limit", 500)))
    except ValueError:
        return build_response(error="Invalid limit", status=400, event=event)

    # Parse lastKey for pagination
    try:
        last_key = json.loads(params["lastKey"]) if params.get("lastKey") else None
    except json.JSONDecodeError:
        return build_response(error="Invalid lastKey", status=400, event=event)

    # Policy check: Projects.view
    project_record = PROJECTS_TABLE.get_item(Key={"projectID": project_id}).get("Item")
    if not project_record:
        return build_response(error="Project not found", status=404, event=event)

    deny_resp = decision_or_deny(
        event,
        requester_user_id,
        resource="Projects",
        action="view",
        record_id=project_id,
        record_type="project",
        resource_object=project_record,
    )
    if deny_resp:
        return deny_resp

    # Query project assignments
    query_params = {
        "IndexName": "GSI_ProjectID",
        "KeyConditionExpression": Key("projectID").eq(project_id),
        "Limit": limit
    }
    if last_key:
        query_params["ExclusiveStartKey"] = last_key

    try:
        resp = ASSIGNMENTS_TABLE.query(**query_params)
        assignments = resp.get("Items", [])
        next_key = resp.get("LastEvaluatedKey")
    except Exception as e:
        return build_response(error=f"Query failed: {e}", status=500, event=event)

    if not assignments:
        return build_response(data={"users": []}, status=200, event=event)

    users_info = []

    for assignment in assignments:
        assignment_id = assignment.get("assignmentID")
        user_id = assignment.get("userID")

        # Policy check: ProjectAssignments.view
        deny_resp = decision_or_deny(
            event,
            requester_user_id,
            resource="ProjectAssignments",
            action="view",
            record_id=assignment_id,
            record_type="assignment",
            resource_object=assignment,
        )
        if deny_resp:
            continue

        # Fetch user record (for roles)
        user_record = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item") if user_id else None
        role_name = ""
        if user_record:
            roles = user_record.get("roles", [])
            role_name = roles[0] if roles else ""

        # Fetch employee record (profile fields)
        employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": user_id}).get("Item") if user_id else None
        employee_email = ""
        employee_designation = ""
        employee_display_id = ""
        employee_full_name = ""
        if employee_record:
            first_name = employee_record.get("firstName", "")
            last_name = employee_record.get("lastName", "")
            employee_full_name = f"{first_name} {last_name}".strip()
            employee_email = employee_record.get("officialEmail", "")
            employee_designation = employee_record.get("designation", "")
            employee_display_id = employee_record.get("displayID", "")
        else:
            print(f"Employee record not found for userID: {user_id}")

        # Fetch assignedBy details
        assigned_by_user_id = assignment.get("assignedBy")
        assigned_by_role = ""
        assigned_by_full_name = ""

        if assigned_by_user_id:
            assigned_by_record = USERS_TABLE.get_item(Key={"userID": assigned_by_user_id}).get("Item")
            if assigned_by_record:
                assigned_by_role = assigned_by_record.get("roles", [])[0] if assigned_by_record.get("roles") else ""

            assigned_by_employee_record = EMPLOYEES_TABLE.get_item(Key={"employeeID": assigned_by_user_id}).get("Item")
            if assigned_by_employee_record:
                assigned_by_full_name = f"{assigned_by_employee_record.get('firstName', '')} {assigned_by_employee_record.get('lastName', '')}".strip()

        # Build user response
        users_info.append({
            "userID": user_id,
            "username": employee_full_name,
            "email": employee_email,
            "designation": employee_designation,
            "displayID": employee_display_id,
            "role": role_name,
            "assignedBy": assigned_by_user_id,
            "assignedByRole": assigned_by_role,
            "assignedByName": assigned_by_full_name,
            "status": assignment.get("status", ""),
            "assignedAt": format_date_to_mm_dd_yyyy(assignment.get("assignedAt", "")),
            "assignmentID": assignment_id,
            "assignmentDisplayID": assignment.get("displayID", "")
        })

    # Prepare response payload
    payload = {"users": users_info}
    if next_key:
        payload["nextKey"] = json.dumps(next_key)

    return build_response(data=payload, status=200, event=event)








# ——— Get Unassigned Members Function ———
def handle_get_unassigned_members(request_event, requesting_user_id):

    # Parse query parameters
    query_params = request_event.get("queryStringParameters") or {}
    project_identifier = (query_params.get("projectID") or "").strip()
    if not project_identifier:
        return build_response(error="projectID is required", status=400, event=request_event)

    # Parse limit
    try:
        page_limit = max(1, int(query_params.get("limit", 500)))
    except ValueError:
        return build_response(error="Invalid limit", status=400, event=request_event)

    # Ensure project exists
    project_item = PROJECTS_TABLE.get_item(Key={"projectID": project_identifier}).get("Item")
    if not project_item:
        return build_response(error="Project not found", status=404, event=request_event)

    # Policy check: Projects.view
    deny = decision_or_deny(
        request_event,
        requesting_user_id,
        "Projects",
        "view",
        record_id=project_identifier,
        record_type="project",
        resource_object=project_item,
    )
    if deny:
        return deny

    # Policy check: ProjectAssignments.create
    deny = decision_or_deny(
        request_event,
        requesting_user_id,
        "ProjectAssignments",
        "create",
        record_id=project_identifier,
        record_type="project",
        resource_object=project_item,
    )
    if deny:
        return deny

    # Gather assigned user IDs for this project
    try:
        resp = ASSIGNMENTS_TABLE.query(
            IndexName="GSI_ProjectID",
            KeyConditionExpression=Key("projectID").eq(project_identifier),
            ProjectionExpression="userID, #status",
            ExpressionAttributeNames={"#status": "status"},
        )
        assigned_user_ids = {
            item["userID"]
            for item in resp.get("Items", [])
            if item.get("status") == "Active" and item.get("userID")
        }
    except Exception as e:
        return build_response(error=f"Failed to fetch assignments: {e}", status=500, event=request_event)

    # Scan all users
    try:
        resp = USERS_TABLE.scan(
            ProjectionExpression="userID, #roles, #status",
            ExpressionAttributeNames={"#roles": "roles", "#status": "status"},
            Limit=page_limit
        )
        user_items = resp.get("Items", [])
        next_key = resp.get("LastEvaluatedKey")
    except Exception as e:
        return build_response(error=f"Failed to fetch users: {e}", status=500, event=request_event)

    seen_user_ids = set()
    unassigned_members = []

    for user_item in user_items:
        user_id_value = user_item.get("userID")
        roles_value = user_item.get("roles", []) or []
        status_value = user_item.get("status", "")

        # Skip invalid, already assigned, inactive, or admin users
        if not user_id_value or user_id_value in assigned_user_ids or user_id_value in seen_user_ids:
            continue
        if status_value != "Active":
            continue
        if any(r.lower() in ("admin", "super admin") for r in roles_value):
            continue

        # Fetch employee profile for username & email
        employee_item = EMPLOYEES_TABLE.get_item(Key={"employeeID": user_id_value}).get("Item") or {}
        seen_user_ids.add(user_id_value)

        role_value = roles_value[0] if isinstance(roles_value, list) and roles_value else None

        # Add unassigned member entry
        unassigned_members.append({
            "userID": user_id_value,
            "username": employee_item.get("fullName")
            or f"{employee_item.get('firstName','')} {employee_item.get('lastName','')}".strip(),
            "email": employee_item.get("officialEmail", ""),
            "role": role_value,
        })

    # Build response
    response_payload = {"unassignedMembers": unassigned_members}
    if next_key:
        response_payload["nextKey"] = json.dumps(next_key)

    return build_response(data=response_payload, status=200, event=request_event)


# ——— Delete Assignments Function ———
def handle_delete_assignment(request_event, requesting_user_id, request_body):

    # Validate input
    assignment_identifier_list = request_body.get("assignmentIDs")
    if not isinstance(assignment_identifier_list, list) or not assignment_identifier_list:
        return build_response(error="assignmentIDs is required", status=400, event=request_event)

    deleted_counter = 0

    for assignment_identifier in assignment_identifier_list:

        # Load assignment record
        assignment_record = ASSIGNMENTS_TABLE.get_item(Key={"assignmentID": assignment_identifier}).get("Item")
        if not assignment_record:
            return build_response(error=f"Assignment {assignment_identifier} not found", status=404, event=request_event)

        project_id = assignment_record.get("projectID")

        # Prevent self-deletion
        if assignment_record.get("userID") == requesting_user_id:
            return build_response(error="Cannot delete your own assignment", status=403, event=request_event)

        # Policy check: Projects.view
        deny = decision_or_deny(
            request_event,
            requesting_user_id,
            "Projects",
            "view",
            record_id=project_id,
            record_type="project",
            resource_object={"projectID": project_id}
        )
        if deny:
            return deny

        # Enrich assignment with createdBy via GSI on assignedBy
        try:
            gsi_resp = ASSIGNMENTS_TABLE.query(
                IndexName="GSI_AssignedBy",
                KeyConditionExpression=Key("assignedBy").eq(requesting_user_id),
                ProjectionExpression="assignmentID"
            )
            self_assignments = {item["assignmentID"] for item in gsi_resp.get("Items", [])}
        except Exception:
            self_assignments = set()

        resource_object = dict(assignment_record)
        if assignment_identifier in self_assignments:
            resource_object["createdBy"] = requesting_user_id  # Tag for "self" scope match

        # Policy check: ProjectAssignments.view
        deny = decision_or_deny(
            request_event,
            requesting_user_id,
            "ProjectAssignments",
            "view",
            record_id=assignment_identifier,
            record_type="assignment",
            resource_object=resource_object
        )
        if deny:
            return deny

        # Policy check: ProjectAssignments.delete
        deny = decision_or_deny(
            request_event,
            requesting_user_id,
            "ProjectAssignments",
            "delete",
            record_id=assignment_identifier,
            record_type="assignment",
            resource_object=resource_object
        )
        if deny:
            return deny

        # Delete assignment
        ASSIGNMENTS_TABLE.delete_item(Key={"assignmentID": assignment_identifier})
        deleted_counter += 1

    # Success response
    return build_response(
        event=request_event,
        status=200,
        data={"message": f"Deleted {deleted_counter} assignment(s)"}
    )
