import json
import uuid
from datetime import datetime

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr, Key

from utils import *
from utils import decision_or_deny


# ——— Create Task Handler ———
def handle_add_task(body, requester_id, event):

    # Extract input fields
    task_name = body.get("taskName", "").strip()
    project_id = body.get("projectID")
    assigned_to = body.get("assignedTo")

    # Validate required fields
    if not task_name or not project_id:
        return build_response(
            error="taskName and projectID are required",
            status=400,
            event=event
        )

    # Check if project exists
    project = PROJECTS_TABLE.get_item(Key={"projectID": project_id}).get("Item")
    if not project:
        return build_response(error="Project not found", status=404, event=event)

    # Policy check: must be able to view project
    resp = decision_or_deny(
        event,
        requester_id,
        resource="Projects",
        action="view",
        record_id=project_id,
        resource_object=project,
    )
    if resp:
        return resp

    # Policy check: must be able to create task
    resp = decision_or_deny(
        event,
        requester_id,
        resource="Tasks",
        action="create",
        record_id=project_id,
        resource_object=project,
        extra_context={"projectID": project_id},
    )
    if resp:
        return resp

    # Duplicate task check (only when assigned user is provided)
    if assigned_to:
        task_dup = TASKS_TABLE.query(
            IndexName="ProjectAssignedIndex",
            KeyConditionExpression=Key("projectID").eq(project_id) & Key("assignedTo").eq(assigned_to),
            FilterExpression=Attr("taskName").eq(task_name) & Attr("status").eq("Active")
        )
        if task_dup.get("Count", 0) > 0:
            return build_response(
                error="An active task with this name already exists for that user on this project",
                status=400,
                event=event
            )

    # Create new task record
    now_iso = datetime.utcnow().isoformat()
    task_id = str(uuid.uuid4())

    task_item = {
        "taskID":     task_id,
        "displayID":  generate_unique_display_id("TSK"),
        "taskName":   task_name,
        "projectID":  project_id,
        "createdBy":  requester_id,
        "entityType": "Task",
        "createdAt":  now_iso,
        "updatedAt":  now_iso,
        "updatedBy":  requester_id,
        "status":     "Active"
    }

    # Add assignment if provided
    if assigned_to:
        task_item["assignedTo"] = assigned_to
        task_item["assignedAt"] = now_iso

    # Insert task record
    TASKS_TABLE.put_item(Item=task_item)

    # Build response message
    msg = f"Task '{task_name}' created"
    if assigned_to:
        msg += f" and assigned to user '{assigned_to}'"

    # Success response
    return build_response(
        data={"message": msg},
        status=201,
        event=event
    )






# ——— Get Tasks Function ———
def handle_get_tasks(event, requester_user_id):

    # Extract query params
    params = event.get("queryStringParameters") or {}
    project_id = params.get("projectID")
    view_mode  = params.get("view")
    last_key   = params.get("lastKey")

    # Validate pagination limit
    try:
        page_limit = int(params.get("limit", 30))
        if page_limit <= 0:
            raise ValueError("must be positive")
    except ValueError as exc:
        return build_response(error=f"Invalid limit: {exc}", status=400, event=event)

    # Member "task_assign" view
    if view_mode == "task_assign":
        if not project_id:
            return build_response(error="projectID is required for member view", status=400, event=event)

        # Policy check: Projects.view
        project_check = decision_or_deny(event, requester_user_id, "Projects", "view", record_id=project_id)
        if project_check:
            return project_check

        # Fetch all assignments for the project
        assignment_query = ASSIGNMENTS_TABLE.query(
            IndexName="GSI_ProjectID",
            KeyConditionExpression=Key("projectID").eq(project_id),
            ProjectionExpression="assignmentID, userID, projectID, assignedBy"
        )
        project_assignments = assignment_query.get("Items", []) or []

        # No assignments found
        if not project_assignments:
            return build_response(
                data={"members": [], "totalCount": 0, "message": "No members found for the project"},
                status=200,
                event=event
            )

        # Build allowed members list
        allowed_members = [
            {
                "userID": assignment["userID"],
                "username": get_user_full_name(assignment["userID"])
            }
            for assignment in project_assignments
        ]

        return build_response(
            data={"members": allowed_members, "totalCount": len(allowed_members)},
            status=200,
            event=event
        )

    # Fetch tasks (by project or globally)
    if project_id:
        # Policy check: Projects.view
        project_check = decision_or_deny(event, requester_user_id, "Projects", "view", record_id=project_id)
        if project_check:
            return project_check

        # Query tasks by projectID
        query_args = {
            "IndexName": "ProjectIndex",
            "KeyConditionExpression": Key("projectID").eq(project_id),
            "Limit": page_limit
        }
        if last_key:
            query_args["ExclusiveStartKey"] = {"projectID": project_id, "taskID": last_key}

        tasks_query = TASKS_TABLE.query(**query_args)
        fetched_tasks = tasks_query.get("Items", []) or []
        next_key = tasks_query.get("LastEvaluatedKey", {}).get("taskID")

    else:
        # Global scan
        scan_args = {"Limit": page_limit}
        if last_key:
            scan_args["ExclusiveStartKey"] = {"taskID": last_key}

        tasks_scan = TASKS_TABLE.scan(**scan_args)
        fetched_tasks = tasks_scan.get("Items", []) or []
        next_key = tasks_scan.get("LastEvaluatedKey", {}).get("taskID")

    # No tasks found
    if not fetched_tasks:
        return build_response(
            data={"tasks": [], "totalCount": 0, "message": "No tasks found for the project"},
            status=200,
            event=event
        )

    # Per-task filtering with Tasks.view
    authorized_tasks = []
    for task in fetched_tasks:
        task_check = decision_or_deny(
            event,
            requester_user_id,
            "Tasks",
            "view",
            record_id=task["taskID"],
            resource_object=task,
        )
        if not task_check:  # allowed
            authorized_tasks.append(task)

    # Tasks exist but none visible
    if not authorized_tasks:
        return build_response(
            error="Not authorized to Tasks.view (no matching records in scope)",
            status=403,
            event=event
        )

    # Enrich task results
    for task in authorized_tasks:
        task["createdAt"]      = format_date_mmddyyyy(task.get("createdAt", ""))
        task["updatedAt"]      = format_date_mmddyyyy(task.get("updatedAt", ""))
        task["assignedAt"]     = format_date_mmddyyyy(task.get("assignedAt", ""))
        task["assignedToName"] = get_user_full_name(task.get("assignedTo")) if task.get("assignedTo") else None
        task["createdByName"]  = get_user_full_name(task["createdBy"])
        task["updatedByName"]  = get_user_full_name(task["updatedBy"])

    # Build response payload
    payload = {
        "tasks": authorized_tasks,
        "totalCount": len(authorized_tasks),
        "lastKey": next_key
    }

    return build_response(data=payload, status=200, event=event)






# ——— Update Task Function ———
def handle_update_task(request_body, requester_user_id, event=None):

    # Validate taskIDs
    task_ids = request_body.get("taskIDs")
    if not isinstance(task_ids, list) or not task_ids or any(not isinstance(task_id, str) for task_id in task_ids):
        return build_response(error="taskIDs must be a non-empty list of strings", status=400, event=event)

    now_iso = datetime.utcnow().isoformat()
    valid_statuses = {"Active", "Completed", "Pending"}

    # Prepare field updates
    update_fields, remove_fields = {}, []

    # Task name update
    if "taskName" in request_body:
        new_name = request_body["taskName"].strip()
        if not new_name:
            return build_response(error="taskName cannot be empty", status=400, event=event)
        update_fields["taskName"] = new_name

    # Status update
    if "status" in request_body:
        new_status = request_body["status"]
        if new_status not in valid_statuses:
            return build_response(error=f"Invalid status '{new_status}'", status=400, event=event)
        update_fields["status"] = new_status

    # Assignment update
    if "assignedTo" in request_body:
        new_assignee_id = request_body["assignedTo"]
        if new_assignee_id:
            update_fields["assignedTo"] = new_assignee_id
            update_fields["assignedAt"] = now_iso
        else:
            remove_fields += ["assignedTo", "assignedAt"]

    # Ensure at least one field to update
    if not update_fields and not remove_fields:
        return build_response(error="No valid fields to update", status=400, event=event)

    # Build DynamoDB Update Expression
    expr_names, expr_values, set_parts = {}, {}, []
    field_index = 1

    # Build SET parts
    for field, value in update_fields.items():
        name_key, value_key = f"#f{field_index}", f":v{field_index}"
        expr_names[name_key] = field
        expr_values[value_key] = value
        set_parts.append(f"{name_key} = {value_key}")
        field_index += 1

    # Build REMOVE parts
    remove_parts = []
    for field in remove_fields:
        name_key = f"#f{field_index}"
        expr_names[name_key] = field
        remove_parts.append(name_key)
        field_index += 1

    # Final update expression
    update_expression = ""
    if set_parts:
        update_expression = "SET " + ", ".join(set_parts)
    if remove_parts:
        update_expression += (" " if update_expression else "") + "REMOVE " + ", ".join(remove_parts)

    # Process each task
    for task_id in task_ids:
        task_item = TASKS_TABLE.get_item(Key={"taskID": task_id}).get("Item")
        if not task_item:
            return build_response(error="Task not found", status=404, event=event)

        project_id = task_item.get("projectID")

        # Project permission check
        project_check = decision_or_deny(
            event,
            requester_user_id,
            "Projects",
            "view",
            record_id=project_id,
            resource_object={"projectID": project_id}
        )
        if project_check:
            return build_response(error="Not authorized for Projects.view", status=403, event=event)

        # Task view check
        task_view_check = decision_or_deny(
            event,
            requester_user_id,
            "Tasks",
            "view",
            record_id=task_id,
            resource_object=task_item,
        )
        if task_view_check:
            return build_response(error="Not authorized for Tasks.view", status=403, event=event)

        # Task modify check
        task_modify_check = decision_or_deny(
            event,
            requester_user_id,
            "Tasks",
            "modify",
            record_id=task_id,
            resource_object=task_item,
        )
        if task_modify_check:
            return build_response(error="Not authorized for Tasks.modify", status=403, event=event)

        # Apply update in DynamoDB
        try:
            TASKS_TABLE.update_item(
                Key={"taskID": task_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values
            )
        except Exception as ex:
            return build_response(error=f"Update failed: {ex}", status=500, event=event)

    # Success response
    return build_response(
        data={"message": f"Successfully updated {len(task_ids)} task(s)"},
        status=200,
        event=event
    )












# ——— Delete Task Function ———
def handle_delete_task(request_body, requester_user_id, event):

    # Validate taskIDs
    task_ids = request_body.get("taskIDs")
    if not isinstance(task_ids, list) or not task_ids or any(not isinstance(tid, str) for tid in task_ids):
        return build_response(
            error="taskIDs must be a non-empty list of strings",
            status=400,
            event=event
        )

    deleted_task_ids = []

    # Process each task
    for task_id in task_ids:

        # Fetch task record
        task_record = TASKS_TABLE.get_item(Key={"taskID": task_id}).get("Item")
        if not task_record:
            return build_response(
                error="Task not found",
                status=404,
                event=event
            )

        project_id = task_record.get("projectID")

        # Project permission check
        project_check = decision_or_deny(
            event,
            requester_user_id,
            "Projects",
            "view",
            record_id=project_id,
            resource_object={"projectID": project_id}
        )
        if project_check:
            return build_response(error="Not authorized for Projects.view", status=403, event=event)

        # Task view permission check
        task_view_check = decision_or_deny(
            event,
            requester_user_id,
            "Tasks",
            "view",
            record_id=task_id,
            resource_object=task_record,
        )
        if task_view_check:
            return build_response(error="Not authorized for Tasks.view", status=403, event=event)

        # Task delete permission check
        task_delete_check = decision_or_deny(
            event,
            requester_user_id,
            "Tasks",
            "delete",
            record_id=task_id,
            resource_object=task_record,
        )
        if task_delete_check:
            return build_response(error="Not authorized for Tasks.delete", status=403, event=event)

        # Perform delete
        try:
            TASKS_TABLE.delete_item(Key={"taskID": task_id})
            deleted_task_ids.append(task_id)
        except Exception as ex:
            return build_response(error=f"Delete failed: {ex}", status=500, event=event)

    # Build response
    if deleted_task_ids:
        return build_response(
            data={"message": f"Deleted {len(deleted_task_ids)} task(s) successfully"},
            status=200,
            event=event
        )

    return build_response(error="No tasks deleted", status=400, event=event)
