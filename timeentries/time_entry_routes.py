# ——— Standard Library Imports ———
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta
from decimal import Decimal
import json
import time
import traceback
from uuid import uuid4

# ——— Third-Party Library Imports ———
import boto3
import botocore
import urllib.parse
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

# ——— Local Application Imports ———
from pto_routes import is_on_approved_pto
from utils import decision_or_deny
from utils import *

# ——— AWS Clients ———
dynamodb = boto3.client("dynamodb")
dynamodb_resource = boto3.resource("dynamodb")
s3_client = boto3.client("s3")

# ——— Main Entry Point ———
def handle_create_or_update(event, auth):
    try:
        request_body = json.loads(event.get("body", "{}"))
    except Exception:
        # Invalid JSON body
        return build_response(error="Invalid JSON in request body.", status=400, event=event)

    actor_user_id = auth.get("user_id")
    timestamp_iso8601 = datetime.utcnow().isoformat()

    # Default to "daily" if not provided
    requested_entry_type = (request_body.get("entryType") or "daily").lower()

    if requested_entry_type == "daily":
        return _handle_daily_entry(
            request_body,
            actor_user_id,
            timestamp_iso8601,
            event,
            "daily",
        )
    elif requested_entry_type == "weekly":
        return _handle_weekly_entry(
            request_body,
            actor_user_id,
            timestamp_iso8601,
            event,
            "weekly",
        )
    else:
        # Only "daily" and "weekly" are valid
        return build_response(error="Invalid entryType. Must be 'daily' or 'weekly'.", status=400, event=event)


# ——— Allowed Schema ———
ALLOWED_FIELDS = {
    "TimeEntryID", "clientID", "Date", "EntryType", "descriptionText", "descriptionFileURL",
    "isApproved", "RegularHours", "OvertimeHours", "TotalHoursWorked", "status",
    "projectID", "submittedBy", "taskID", "tags", "UserProjTaskPK", "UserID",
    "createdAt", "createdBy", "updatedAt", "updatedBy"
}

def filter_fields(item: dict) -> dict:
    # Keep only the allowed schema fields before saving to DB
    return {k: v for k, v in item.items() if k in ALLOWED_FIELDS}


# ——— File Upload Helper ———
def resolve_file_upload(previous_url, incoming_file, incoming_name,
                        user_name, project_name, time_entry_id):
    if not incoming_file:
        return previous_url  # No new file, keep existing
    
    if previous_url:
        delete_s3_file(previous_url)  # Replace old file if it exists

    upload_result, upload_err = upload_description_to_s3(
        user_name, project_name, time_entry_id, incoming_file, file_name=incoming_name
    )
    if upload_err:
        raise ValueError(upload_err)
    
    return upload_result["url"]


# ——— Reset Rejected Entry Helper ———
def reset_rejected_entry(time_entry_id):
    # Reset main entry to Pending + clear approval
    ENTRIES_TABLE.update_item(
        Key={"TimeEntryID": time_entry_id},
        UpdateExpression="SET #st = :s, isApproved = :ia",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "Pending", ":ia": False},
    )

    # Reset related approvals back to Pending
    approvals = APPROVAL_TABLE.query(
        IndexName="TimeEntryID-index",
        KeyConditionExpression=Key("TimeEntryID").eq(time_entry_id),
        ProjectionExpression="ApprovalID, ManagerID",
    ).get("Items", [])

    for approval in approvals:
        APPROVAL_TABLE.update_item(
            Key={"ApprovalID": approval["ApprovalID"], "ManagerID": approval["ManagerID"]},
            UpdateExpression="SET ApprovalStatus = :ps REMOVE ApprovedAt, ApprovedBy, Comments",
            ExpressionAttributeValues={":ps": "Pending"},
        )



# ——— Shared Upsert for Daily/Weekly ———
def _upsert_entry_for_day(date_iso, hours, project_id, task_id, target_user_id,
                          actor_user_id, project_details, incoming_file, incoming_name,
                          desc_text, tags, timestamp_iso8601, entry_type,
                          existing_entry=None):

    # Block time entry if user is on approved PTO
    if is_on_approved_pto(target_user_id, date_iso):
        raise ValueError(f"User on PTO at {date_iso}")

    # Normalize and split hours into regular/overtime
    hours = float(hours)
    if hours < 0:
        raise ValueError("Negative hours not allowed")
    regular, overtime = min(hours, 8), max(hours - 8, 0)

    # Reuse existing ID if updating, otherwise generate new
    time_entry_id = existing_entry["TimeEntryID"] if existing_entry else str(uuid4())

    # Handle file upload (replace old if provided)
    file_url = resolve_file_upload(
        existing_entry.get("descriptionFileURL") if existing_entry else None,
        incoming_file, incoming_name,
        get_user_name(target_user_id),
        project_details.get("projectName", ""),
        time_entry_id
    )

    # Common fields used for both insert and update
    common = {
        "UserProjTaskPK": f"{target_user_id}#{project_id}#{task_id}",
        "taskID": task_id,
        "Date": date_iso,
        "TotalHoursWorked": Decimal(str(hours)),
        "RegularHours": Decimal(str(regular)),
        "OvertimeHours": Decimal(str(overtime)),
        "descriptionFileURL": file_url,
        "descriptionText": desc_text,
        "tags": tags,
    }

    if existing_entry:
        # Prevent edits if already approved
        if existing_entry.get("isApproved"):
            raise ValueError(f"Already approved on {date_iso}")

        # Reset rejected entry before re-submission
        if existing_entry.get("status") == "Rejected":
            reset_rejected_entry(time_entry_id)

        # Update existing entry
        ENTRIES_TABLE.update_item(
            Key={"TimeEntryID": time_entry_id},
            UpdateExpression=("SET taskID=:tid, TotalHoursWorked=:h, RegularHours=:rh, "
                              "OvertimeHours=:oh, #st=:s, descriptionText=:d, "
                              "descriptionFileURL=:url, tags=:tg, updatedAt=:u, "
                              "updatedBy=:ub, submittedBy=:sb, EntryType=:et"),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":tid": task_id, ":h": common["TotalHoursWorked"],
                ":rh": common["RegularHours"], ":oh": common["OvertimeHours"],
                ":s": "Pending", ":d": desc_text, ":url": file_url,
                ":tg": tags, ":u": timestamp_iso8601,
                ":ub": actor_user_id, ":sb": actor_user_id,
                ":et": entry_type,
            },
        )
        return "updated"

    # Insert new entry
    new_item = filter_fields({
        "TimeEntryID": time_entry_id,
        "UserID": target_user_id,
        "projectID": project_id,
        "clientID": project_details.get("clientID", ""),
        "EntryType": entry_type,
        "isApproved": False,
        "status": "Pending",
        "submittedBy": actor_user_id,
        "createdAt": timestamp_iso8601,
        "createdBy": actor_user_id,
        **common,
    })
    ENTRIES_TABLE.put_item(Item=new_item)
    return "created"




# ——— Daily Handler ———
def _handle_daily_entry(request_body, actor_user_id, timestamp_iso8601, event, entry_type="daily"):
    try:
        # Extract required fields from request
        project_id = (request_body.get("projectID") or "").strip()
        entry_date = (request_body.get("date") or "").strip()
        task_id = (request_body.get("taskID") or "").strip()
        target_user_id = request_body.get("userID", actor_user_id)

        # Validate required params
        if not (project_id and entry_date and task_id):
            return build_response(error="Missing projectID, date, or taskID", status=400, event=event)

        # Fetch project (must exist)
        project_record, err = get_project(project_id)
        if err:
            return build_response(error="Project not found", status=404, event=event)

        # ——— Backtrack Validation ———
        if not is_backtrack_approved(target_user_id, project_id, entry_date):
            return build_response(
                error=f"No approved backtrack for {entry_date}",
                status=403,
                event=event
            )

        # Lookup existing entry for this date
        pk = f"{target_user_id}#{project_id}#{task_id}"
        query = ENTRIES_TABLE.query(
            IndexName="UserProjTaskDate-index",
            KeyConditionExpression=Key("UserProjTaskPK").eq(pk) & Key("Date").eq(entry_date),
            ProjectionExpression="TimeEntryID,#st,isApproved,descriptionFileURL,createdBy,#dt",
            ExpressionAttributeNames={"#st": "status", "#dt": "Date"},
        )
        existing = query.get("Items", [])
        existing_entry = existing[0] if existing else None

        # Policy check: Records.modify (update) or Records.create (new)
        if existing_entry:
            rec_scope = get_allowed_record_ids(actor_user_id, "TimeEntries", "records_modify")
            action_type = "modify"
        else:
            rec_scope = get_allowed_record_ids(actor_user_id, "TimeEntries", "records_create")
            action_type = "create"

        rec_scopes, rec_all, rec_selected = (
            rec_scope.get("scopes", []),
            rec_scope.get("all", False),
            rec_scope.get("ids") or [],
        )

        # Enforce access rules
        if "none" in rec_scopes:
            return build_response(error=f"Not authorized to {action_type} records", status=403, event=event)

        if not (
            rec_all
            or ("self" in rec_scopes and actor_user_id == target_user_id)
            or ("selected" in rec_scopes and target_user_id in rec_selected)
        ):
            return build_response(error=f"Not authorized to {action_type} record for this user", status=403, event=event)

        # Insert or update the entry
        result = _upsert_entry_for_day(
            entry_date,
            request_body.get("totalHoursWorked", 0),
            project_id,
            task_id,
            target_user_id,
            actor_user_id,
            project_record,
            request_body.get("descriptionFileBase64") or request_body.get("descriptionFileURL"),
            request_body.get("descriptionFileName"),
            request_body.get("description", ""),
            request_body.get("tags", []),
            timestamp_iso8601,
            entry_type,
            existing_entry=existing_entry,
        )

        # Respond with status depending on insert/update
        return build_response(
            data={"message": f"Entry {result}"},
            status=200 if result == "updated" else 201,
            event=event,
        )

    except Exception as e:
        return build_response(error=str(e), status=500, event=event)









# ——— Weekly Handler ———
def _handle_weekly_entry(request_body, actor_user_id, timestamp_iso8601, event, entry_type="weekly"):
    try:
        # Extract basic params
        target_user_id = request_body.get("userID", actor_user_id)
        week_start_str = (request_body.get("weekStartDate") or "").strip()
        blocks = request_body.get("entries") or []

        # Validate required params
        if not week_start_str or not blocks:
            return build_response(error="Missing weekStartDate or entries", status=400, event=event)

        # Compute week range (Mon → Sun)
        start_date = datetime.fromisoformat(week_start_str).date()
        week_start = start_date - timedelta(days=start_date.weekday())
        week_end = week_start + timedelta(days=6)

        created, updated = [], []

        for block in blocks:
            # Extract block fields
            project_id = (block.get("projectID") or "").strip()
            task_id = (block.get("taskID") or "").strip()
            hours_map = block.get("dailyHours") or {}
            timeentry_ids_map = block.get("timeEntryIds", {})  # optional IDs from payload

            if not project_id or not task_id or not hours_map:
                return build_response(error="Missing projectID, taskID, or dailyHours", status=400, event=event)

            # Fetch project (must exist)
            project_record, err = get_project(project_id)
            if err:
                return build_response(error=f"Project not found: {project_id}", status=404, event=event)

            # ——— Backtrack Validation (collect all missing approvals at once) ———
            missing_backtracks = [
                date_iso for date_iso in hours_map.keys()
                if not is_backtrack_approved(target_user_id, project_id, date_iso)
            ]
            if missing_backtracks:
                return build_response(
                    error=f"No approved backtrack for dates: {', '.join(sorted(missing_backtracks))}",
                    status=403,
                    event=event
                )

            # Fetch existing entries for the week
            pk = f"{target_user_id}#{project_id}#{task_id}"
            existing_query = ENTRIES_TABLE.query(
                IndexName="UserProjTaskDate-index",
                KeyConditionExpression=Key("UserProjTaskPK").eq(pk) & Key("Date").between(
                    week_start.isoformat(), week_end.isoformat()
                ),
                ProjectionExpression="#dt,TimeEntryID,#st,isApproved,descriptionFileURL,createdBy",
                ExpressionAttributeNames={"#st": "status", "#dt": "Date"},
            )
            existing = {i["Date"]: i for i in existing_query.get("Items", [])}

            # File and metadata fields
            incoming_file = block.get("descriptionFileBase64") or block.get("descriptionFileURL")
            incoming_name = block.get("descriptionFileName")
            desc_text = block.get("description", "")
            tags = block.get("tags", [])

            for date_iso, raw_hours in hours_map.items():
                existing_entry = None

                # Try provided TimeEntryID first
                entry_id_from_payload = timeentry_ids_map.get(date_iso)
                if entry_id_from_payload:
                    resp = ENTRIES_TABLE.get_item(Key={"TimeEntryID": entry_id_from_payload})
                    existing_entry = resp.get("Item")

                # Fallback to weekly query result
                if not existing_entry:
                    existing_entry = existing.get(date_iso)

                # Policy checks
                if existing_entry:  # modify existing entry
                    rec_scope = get_allowed_record_ids(actor_user_id, "TimeEntries", "records_modify")
                    rec_scopes, rec_all, rec_selected = rec_scope.get("scopes", []), rec_scope.get("all", False), rec_scope.get("ids") or []
                    if "none" in rec_scopes:
                        return build_response(error="Not authorized to modify records", status=403, event=event)
                    if not (
                        rec_all or "all" in rec_scopes or
                        ("self" in rec_scopes and actor_user_id == target_user_id) or
                        ("selected" in rec_scopes and target_user_id in rec_selected)
                    ):
                        return build_response(error="Not authorized to modify this record", status=403, event=event)
                else:  # create new entry
                    rec_scope = get_allowed_record_ids(actor_user_id, "TimeEntries", "records_create")
                    rec_scopes, rec_all, rec_selected = rec_scope.get("scopes", []), rec_scope.get("all", False), rec_scope.get("ids") or []
                    if "none" in rec_scopes:
                        return build_response(error="Not authorized to create records", status=403, event=event)
                    if not (
                        rec_all or "all" in rec_scopes or
                        ("self" in rec_scopes and actor_user_id == target_user_id) or
                        ("selected" in rec_scopes and target_user_id in rec_selected)
                    ):
                        return build_response(error="Not authorized to create record for this user", status=403, event=event)

                # Insert or update entry
                try:
                    result = _upsert_entry_for_day(
                        date_iso,
                        raw_hours,
                        project_id,
                        task_id,
                        target_user_id,
                        actor_user_id,
                        project_record,
                        incoming_file,
                        incoming_name,
                        desc_text,
                        tags,
                        timestamp_iso8601,
                        entry_type,
                        existing_entry=existing_entry,
                    )
                    if result == "updated":
                        updated.append(date_iso)
                    else:
                        created.append(date_iso)
                except ValueError as ve:
                    return build_response(error=str(ve), status=400, event=event)

        # Return summary of created/updated
        return build_response(data={"created": created, "updated": updated}, status=200, event=event)

    except Exception as e:
        return build_response(error=str(e), status=500, event=event)















# ——— Handle Time Summary Function ———
def handle_time_summary(event, auth):
    """Summarize time entries by user → client → project → task with policy checks for Reports."""

    requester_id = auth.get("user_id")
    timestamp_iso8601 = datetime.utcnow().isoformat()

    # ——— Extract Query Parameters from API call ———
    params = event.get("queryStringParameters") or {}
    start_date, end_date = params.get("startDate"), params.get("endDate")
    filter_user_id, filter_project_id, filter_client_id, filter_task_id = (
        params.get("userID"),
        params.get("projectID"),
        params.get("clientID"),
        params.get("taskID"),
    )

    # ——— Validate startDate and endDate ———
    if not start_date or not end_date:
        return build_response(error="startDate and endDate are required", status=400, event=event)
    try:
        datetime.fromisoformat(start_date)
        datetime.fromisoformat(end_date)
    except ValueError:
        return build_response(error="Invalid date format. Use YYYY-MM-DD.", status=400, event=event)

    # ——— Check Reports Policy Permissions ———
    reports_scope = get_allowed_record_ids(requester_id, "Reports", "view")
    if "none" in reports_scope.get("scopes", []):
        return build_response(error="Not authorized to view reports", status=403, event=event)

    allowed_ids = reports_scope.get("ids") or []
    scopes = reports_scope.get("scopes", [])
    allow_all = reports_scope.get("all", False)

    def is_allowed_for_user(uid: str) -> bool:
        """Decide if this user's data can be included."""
        if allow_all:
            return True
        if "self" in scopes and uid == requester_id:
            return True
        if "selected" in scopes and uid in allowed_ids:
            return True
        return False

    # ——— Fetch time entries (query by filters, or daily loop on Date-index) ———
    def fetch_time_entries():
        if filter_user_id:
            return ENTRIES_TABLE.query(
                IndexName="UserDate-index",
                KeyConditionExpression=Key("UserID").eq(filter_user_id) & Key("Date").between(start_date, end_date)
            ).get("Items", [])

        if filter_project_id:
            return ENTRIES_TABLE.query(
                IndexName="ProjectDate-index",
                KeyConditionExpression=Key("projectID").eq(filter_project_id) & Key("Date").between(start_date, end_date)
            ).get("Items", [])

        if filter_client_id:
            return ENTRIES_TABLE.query(
                IndexName="ClientDate-index",
                KeyConditionExpression=Key("clientID").eq(filter_client_id) & Key("Date").between(start_date, end_date)
            ).get("Items", [])

        # No filters → loop over days in range
        d0 = datetime.fromisoformat(start_date).date()
        d1 = datetime.fromisoformat(end_date).date()
        days = [(d0 + timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]

        def query_day(day):
            resp = ENTRIES_TABLE.query(
                IndexName="Date-index",
                KeyConditionExpression=Key("Date").eq(day)
            )
            return resp.get("Items", [])

        from concurrent.futures import ThreadPoolExecutor
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for items in executor.map(query_day, days):
                results.extend(items)

        return results

    # ——— Get entries and apply policy filter ———
    raw_items = fetch_time_entries()
    items = [i for i in raw_items if is_allowed_for_user(i.get("UserID"))]

    if not items:
        return build_response(error="No time entries found", status=200, event=event)

    # ——— Collect IDs for batch lookups ———
    user_ids = {i.get("UserID") for i in items if i.get("UserID")}
    client_ids = {i.get("clientID") for i in items if i.get("clientID")}
    project_ids = {i.get("projectID") for i in items if i.get("projectID")}
    task_ids = {i.get("taskID") for i in items if i.get("taskID")}
    entry_ids = {i.get("TimeEntryID") for i in items if i.get("TimeEntryID")}

    ddb_client = boto3.client("dynamodb")

    # ——— Helper: BatchGet with pagination ———
    def batch_get_paginated(table_name, keys, key_field):
        results = {}
        for i in range(0, len(keys), 100):
            batch = keys[i:i + 100]
            resp = ddb_client.batch_get_item(RequestItems={table_name: {"Keys": batch}})
            for item in resp["Responses"].get(table_name, []):
                k = item[key_field]["S"]
                results[k] = item
        return results

    # ——— Batch fetch projects ———
    project_cache = {}
    if project_ids:
        keys = [{"projectID": {"S": pid}} for pid in project_ids]
        resp = batch_get_paginated(PROJECTS_TABLE.name, keys, "projectID")
        for pid, proj in resp.items():
            project_cache[pid] = proj.get("projectName", {}).get("S", "Project")

    # ——— Batch fetch tasks ———
    task_cache = {}
    if task_ids:
        keys = [{"taskID": {"S": tid}} for tid in task_ids]
        resp = batch_get_paginated(TASKS_TABLE.name, keys, "taskID")
        for tid, task in resp.items():
            task_cache[tid] = task.get("taskName", {}).get("S", "General")

    # ——— User + client caches ———
    user_cache = {uid: get_user_name(uid) for uid in user_ids}
    client_cache = {cid: get_client_name(cid) or "Client" for cid in client_ids}

    # ——— Approvals lookup (batched by entry IDs) ———
    approval_cache = {}
    if entry_ids:
        entry_id_list = list(entry_ids)

        def fetch_batch(eids):
            results = {}
            for eid in eids:
                approval_items = APPROVAL_TABLE.query(
                    IndexName="TimeEntryID-index",
                    KeyConditionExpression=Key("TimeEntryID").eq(eid),
                ).get("Items", [])
                results[eid] = [
                    a["ApprovalID"] for a in approval_items if a.get("ApprovalStatus") == "Pending"
                ]
            return results

        from concurrent.futures import ThreadPoolExecutor
        batch_size = 100  # break into smaller chunks
        tasks = [entry_id_list[i:i + batch_size] for i in range(0, len(entry_id_list), batch_size)]

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(fetch_batch, tasks))

        for r in results:
            approval_cache.update(r)

    # ——— Utility helpers ———
    weekdays_map = iso_to_weekday_map()

    def to_float_hours(value):
        try:
            if isinstance(value, str) and ":" in value:
                h, m = map(int, value.split(":"))
                return h + m / 60.0
            return float(value)
        except Exception:
            return 0.0

    def to_hhmm_string(hours_float):
        h = int(hours_float)
        m = round((hours_float - h) * 60)
        if m == 60:
            h, m = h + 1, 0
        return f"{h:02d}:{m:02d}"

    def make_day_summary(include_approvals=False):
        summary = {wd: {"hours": "00:00"} for wd in weekdays_map.values()}
        if include_approvals:
            for s in summary.values():
                s["approvals"] = []
        summary["grand_total"] = "00:00"
        return summary

    def accumulate_hours(summary_node, totals_per_day):
        for wd, hours in totals_per_day.items():
            current = to_float_hours(summary_node[wd]["hours"])
            summary_node[wd]["hours"] = to_hhmm_string(current + hours)
        summary_node["grand_total"] = to_hhmm_string(
            sum(to_float_hours(summary_node[wd]["hours"]) for wd in weekdays_map.values())
        )

    # ——— Build summary hierarchy (stream as we go) ———
    summary_tree, user_nodes = [], {}

    for entry in items:
        if entry.get("isPTO"):
            continue

        uid, cid, pid, tid, eid = (
            entry.get("UserID"),
            entry.get("clientID"),
            entry.get("projectID"),
            entry.get("taskID"),
            entry.get("TimeEntryID"),
        )

        user_name = user_cache.get(uid, "User")
        client_name = client_cache.get(cid, "Client")
        project_name = project_cache.get(pid, "Project")
        task_name = task_cache.get(tid, "General")
        pending_approvals = approval_cache.get(eid, [])

        # Daily hours check
        day_str = entry.get("Date")
        hrs = to_float_hours(entry.get("TotalHoursWorked", 0))
        if not (start_date <= day_str <= end_date and hrs > 0):
            continue

        # Build hierarchy
        if uid not in user_nodes:
            user_nodes[uid] = {
                "key": str(len(user_nodes)),
                "data": {"user": user_name, "userID": uid ,**make_day_summary()},
                "children": [],
            }
            summary_tree.append(user_nodes[uid])
        user_node = user_nodes[uid]

        client_node = next((c for c in user_node["children"] if c["data"]["client"] == client_name), None)
        if not client_node:
            client_node = {
                "key": f"{user_node['key']}-{len(user_node['children'])}",
                "data": {"client": client_name, **make_day_summary()},
                "children": [],
            }
            user_node["children"].append(client_node)

        project_node = next((p for p in client_node["children"] if p["data"]["project"] == project_name), None)
        if not project_node:
            project_node = {
                "key": f"{client_node['key']}-{len(client_node['children'])}",
                "data": {"project": project_name, **make_day_summary()},
                "children": [],
            }
            client_node["children"].append(project_node)

        task_node = next((t for t in project_node["children"] if t["data"]["task"] == task_name), None)
        if not task_node:
            task_node = {
                "key": f"{project_node['key']}-{len(project_node['children'])}",
                "data": {"task": task_name, **make_day_summary(include_approvals=True)},
            }
            project_node["children"].append(task_node)

        # Roll up hours
        totals_per_day = {wd: 0.0 for wd in weekdays_map.values()}
        weekday_key = weekdays_map[datetime.fromisoformat(day_str).weekday()]
        task_node["data"][weekday_key]["date"] = day_str
        totals_per_day[weekday_key] += hrs
        task_node["data"][weekday_key]["approvals"].extend(pending_approvals)

        for node in (task_node, project_node, client_node, user_node):
            accumulate_hours(node["data"], totals_per_day)

    if not summary_tree:
        return build_response(error="No matching time entries found", status=404, event=event)

    total_hours = sum(to_float_hours(user["data"]["grand_total"]) for user in summary_tree)
    return build_response(
        data={
            "summary": summary_tree,
            "totalCount": len(summary_tree),
            "grandTotal": to_hhmm_string(total_hours),
        },
        status=200,
        event=event,
    )














 

# ——— Handle Filter Data ———
def handle_get_filter_data(event, auth):
    """Fetch visible users, projects (with tasks), and time entries in a date range,
       applying TimeEntries.records.view policy checks and excluding approvals."""

    # ——— Extract User Identity ———
    current_user_id = auth.get("user_id")

    # ——— Extract Query Params ———
    query_params = event.get("queryStringParameters") or {}
    date_start, date_end = query_params.get("startDate"), query_params.get("endDate")
    filter_user_id, filter_project_id, filter_client_id = (
        query_params.get("userID"),
        query_params.get("projectID"),
        query_params.get("clientID"),
    )

    # ——— Get TimeEntries.records.view Policy ———
    timesheet_scope = get_allowed_record_ids(current_user_id, "TimeEntries", "records_view")
    allow_all = timesheet_scope.get("all", False)
    scope_ids = timesheet_scope.get("ids") or set()
    scopes = timesheet_scope.get("scopes", [])

    # ——— Fetch Time Entries ———
    def fetch_time_entries():
        # Query by project filter
        if filter_project_id:
            return ENTRIES_TABLE.query(
                IndexName="ProjectDate-index",
                KeyConditionExpression=Key("projectID").eq(filter_project_id) & Key("Date").between(date_start, date_end)
            ).get("Items", [])

        # Query by client filter
        if filter_client_id:
            return ENTRIES_TABLE.query(
                IndexName="ClientDate-index",
                KeyConditionExpression=Key("clientID").eq(filter_client_id) & Key("Date").between(date_start, date_end)
            ).get("Items", [])

        # Query by user filter
        if filter_user_id:
            return ENTRIES_TABLE.query(
                IndexName="UserDate-index",
                KeyConditionExpression=Key("UserID").eq(filter_user_id) & Key("Date").between(date_start, date_end)
            ).get("Items", [])

        # Global query (no filters) → loop over days with parallel queries
        from concurrent.futures import ThreadPoolExecutor
        d0 = datetime.fromisoformat(date_start).date()
        d1 = datetime.fromisoformat(date_end).date()
        days = [(d0 + timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]

        def query_day(day):
            return ENTRIES_TABLE.query(
                IndexName="Date-index",
                KeyConditionExpression=Key("Date").eq(day)
            ).get("Items", [])

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for items in executor.map(query_day, days):
                results.extend(items)
        return results

    raw_time_entries = fetch_time_entries()

    # ——— Apply Policy Filter ———
    if "none" in scopes:
        return build_response(status=403, error="Not authorized to view records", event=event)
    if "selected" in scopes and not scope_ids:
        return build_response(status=403, error="No selected users configured for viewing records", event=event)

    time_entries, accessible_user_ids, accessible_project_ids = [], set(), set()
    for e in raw_time_entries:
        uid = e.get("UserID")

        if allow_all:
            pass
        elif "self" in scopes and uid == current_user_id:
            pass
        elif "selected" in scopes and uid in scope_ids:
            pass
        else:
            continue  # skip unauthorized entry

        time_entries.append(e)
        accessible_user_ids.add(uid)
        accessible_project_ids.add(e.get("projectID"))

    # Return empty if no entries remain
    if not time_entries:
        return build_response(
            data={"users": [], "projects": [], "timeEntries": [], "pendingTimeEntries": []},
            status=200,
            event=event
        )

    # ——— Collect IDs for Prefetch ———
    user_ids = {e["UserID"] for e in time_entries if e.get("UserID")}
    project_ids = set(accessible_project_ids)
    task_ids = {e["taskID"] for e in time_entries if e.get("taskID")}
    entry_ids = {e["TimeEntryID"] for e in time_entries if e.get("TimeEntryID")}

    ddb_client = boto3.client("dynamodb")

    # ——— Batch Project + Task Lookup ———
    project_cache, task_cache, approval_cache = {}, {}, {}
    request_items = {}
    if project_ids:
        request_items[PROJECTS_TABLE.name] = {"Keys": [{"projectID": {"S": pid}} for pid in project_ids]}
    if task_ids:
        request_items[TASKS_TABLE.name] = {"Keys": [{"taskID": {"S": tid}} for tid in task_ids]}

    if request_items:
        resp = ddb_client.batch_get_item(RequestItems=request_items)
        for item in resp["Responses"].get(PROJECTS_TABLE.name, []):
            pid = item["projectID"]["S"]
            project_cache[pid] = item.get("projectName", {}).get("S", "Project")
        for item in resp["Responses"].get(TASKS_TABLE.name, []):
            tid = item["taskID"]["S"]
            task_cache[tid] = item.get("taskName", {}).get("S", "General")

    # ——— Parallel Approvals Lookup ———
    if entry_ids:
        from concurrent.futures import ThreadPoolExecutor
        def fetch_approvals(eid):
            return APPROVAL_TABLE.query(
                IndexName="TimeEntryID-index",
                KeyConditionExpression=Key("TimeEntryID").eq(eid),
            ).get("Items", [])

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(fetch_approvals, entry_ids))
        approval_cache = {eid: items for eid, items in zip(entry_ids, results)}

    # ——— Users Response ———
    users_response = [
        {"userID": uid, "userName": get_user_name(uid)}
        for uid in sorted(accessible_user_ids)
    ]

    # ——— Projects Response ———
    projects_response = []
    for pid in sorted(accessible_project_ids):
        if pid not in project_cache:
            continue

        project_tasks = TASKS_TABLE.query(
            IndexName="ProjectIndex",
            KeyConditionExpression=Key("projectID").eq(pid)
        ).get("Items", [])

        visible_tasks, seen = [], set()
        for task_record in project_tasks:
            tid = task_record.get("taskID")
            tname = task_record.get("taskName", "General")
            assigned_user = task_record.get("assignedTo")
            key = (pid, assigned_user, tname)

            if key not in seen:
                visible_tasks.append({"taskID": tid, "taskName": tname, "assignedTo": assigned_user})
                seen.add(key)

        projects_response.append({
            "projectID": pid,
            "projectName": project_cache.get(pid, "Project"),
            "tasks": visible_tasks
        })

    # ——— Pending Entries ———
    pending_entries = [
        e["TimeEntryID"]
        for e in time_entries
        if e.get("status", "").lower() == "pending" and not approval_cache.get(e["TimeEntryID"])
    ]

    # ——— Group Time Entries by User ———
    def format_hours(hval):
        try:
            f = float(hval)
        except:
            f = 0.0
        h, m = int(f), round((f - int(f)) * 60)
        if m == 60:
            h, m = h + 1, 0
        return f"{h:02d}:{m:02d}"

    grouped = {}
    for e in time_entries:
        uid, pid, tid = e.get("UserID"), e.get("projectID"), e.get("taskID")
        if pid not in project_cache:
            continue
        proj_name = project_cache.get(pid, "Project")
        task_name = task_cache.get(tid, "General")

        grouped.setdefault(uid, []).append({
            "timeEntryID": e.get("TimeEntryID"),
            "projectID": pid,
            "projectName": proj_name,
            "date": e.get("Date"),
            "entryType": e.get("EntryType", ""),
            "fileurl": e.get("descriptionFileURL", ""),
            "totalHours": format_hours(e.get("TotalHoursWorked", 0)),
            "status": e.get("status", ""),
            "task": task_name,
            "taskID": tid,
            "tags": e.get("tags", []),
            "notes": e.get("notes", "")
        })

    time_entries_response = [
        {"userID": uid, "timeEntries": ents}
        for uid, ents in grouped.items()
    ]

    # ——— Final Response ———
    return build_response(
        data={
            "users": users_response,
            "projects": projects_response,
            "timeEntries": time_entries_response,
            "pendingTimeEntries": pending_entries
        },
        status=200,
        event=event,
    )











# ——— Handle Get Users ———
def handle_get_users(event, auth):
    # ——— Extract requester info ———
    current_user_id = auth.get("user_id")
    visible_user_ids = set()  # avoid duplicates

    # ——— Hard deny check ———
    deny = decision_or_deny(event, current_user_id, "TimeEntries", "users_view")
    if deny:
        return deny  # stop immediately if denied

    # ——— Get policy decision ———
    scope_decision = get_allowed_record_ids(
        current_user_id, module="TimeEntries", action="users_view"
    )
    scopes = scope_decision.get("scopes", [])
    has_all = scope_decision.get("all", False)
    selected_ids = scope_decision.get("ids") or []

    # ——— All users allowed ———
    if has_all:
        # use ExpressionAttributeNames to safely alias reserved word "status"
        scan_resp = USERS_TABLE.scan(
            ProjectionExpression="userID, #s",
            FilterExpression=Attr("status").eq("Active"),
            ExpressionAttributeNames={"#s": "status"}
        )

        # collect user ids
        for user in scan_resp.get("Items", []):
            uid = user.get("userID")
            if uid:
                visible_user_ids.add(uid)

        # handle pagination if more data
        while "LastEvaluatedKey" in scan_resp:
            scan_resp = USERS_TABLE.scan(
                ProjectionExpression="userID, #s",
                FilterExpression=Attr("status").eq("Active"),
                ExpressionAttributeNames={"#s": "status"},
                ExclusiveStartKey=scan_resp["LastEvaluatedKey"],
            )
            for user in scan_resp.get("Items", []):
                uid = user.get("userID")
                if uid:
                    visible_user_ids.add(uid)

        if not visible_user_ids:
            return build_response(
                error="No active users found in Users table",
                status=404,
                event=event,
            )

    # ——— Self scope ———
    elif "self" in scopes:
        visible_user_ids.add(current_user_id)

    # ——— Selected users scope ———
    elif "selected" in scopes and selected_ids:
        visible_user_ids.update(selected_ids)
        if not visible_user_ids:
            return build_response(
                error="Not authorized: no valid selected users",
                status=403,
                event=event,
            )

    # ——— Unauthorized scope ———
    else:
        return build_response(
            error="Not authorized to view users",
            status=403,
            event=event,
        )

    # ——— Build response payload ———
    users_payload = []
    for uid in visible_user_ids:
        user_name = get_user_name(uid)  # resolve username
        users_payload.append({
            "userID": uid,
            "userName": user_name
        })

    # ——— Final validation ———
    if not users_payload:
        return build_response(
            error="No authorized user records found",
            status=403,
            event=event,
        )

    # ——— Return response ———
    return build_response(data={"users": users_payload}, status=200, event=event)














# ——— Get User Projects and Tasks Function ———
def handle_user_projects_and_tasks(event, auth):
    """Return authorized projects (and optionally tasks) for a target user based on policy."""

    current_user_id = auth.get("user_id")

    # ——— Extract query params ———
    query_params = event.get("queryStringParameters") or {}
    target_user_id = query_params.get("userID")
    requested_project_id = query_params.get("projectID")

    if not target_user_id:
        return build_response(error="Missing userID parameter", status=400, event=event)

    # ——— Project policy check ———
    project_scope = get_allowed_record_ids(current_user_id, "TimeEntries", "projects_view")
    project_scopes = project_scope.get("scopes", [])
    project_all = project_scope.get("all", False)
    project_selected = project_scope.get("ids") or []

    if "none" in project_scopes:
        return build_response(error="Not authorized for projects_view", status=403, event=event)

    # ——— Fetch active projects for target user ———
    assignments = ASSIGNMENTS_TABLE.query(
        IndexName="UserAssignments-index",
        KeyConditionExpression=Key("userID").eq(target_user_id),
        FilterExpression=Attr("status").eq("Active"),
        ProjectionExpression="projectID"
    ).get("Items", [])

    target_projects = {a["projectID"] for a in assignments}
    if not target_projects:
        return build_response(error="No active projects found for target user", status=404, event=event)

    # ——— Filter projects by policy ———
    allowed_projects = set()
    if project_all:
        allowed_projects.update(target_projects)
    elif "self" in project_scopes and current_user_id == target_user_id:
        allowed_projects.update(target_projects)
    elif "selected" in project_scopes and project_selected:
        allowed_projects.update(set(project_selected) & target_projects)

    if not allowed_projects:
        return build_response(error="Not authorized to view projects", status=403, event=event)

    # ——— Batch fetch projects (with pagination, 100 keys per batch) ———
    ddb_client = boto3.client("dynamodb")
    projects_payload, project_cache = [], {}

    project_keys = [{"projectID": {"S": pid}} for pid in allowed_projects]
    for i in range(0, len(project_keys), 100):  # DynamoDB limit = 100 keys per batch
        batch = project_keys[i:i + 100]
        resp = ddb_client.batch_get_item(RequestItems={PROJECTS_TABLE.name: {"Keys": batch}})
        for item in resp["Responses"].get(PROJECTS_TABLE.name, []):
            pid = item["projectID"]["S"]
            pname = item.get("projectName", {}).get("S", "")
            project_cache[pid] = pname
            projects_payload.append({"projectID": pid, "projectName": pname})

    if not requested_project_id:
        if not projects_payload:
            return build_response(error="No authorized projects available", status=404, event=event)
        return build_response(data={"projects": projects_payload}, status=200, event=event)

    # ——— Validate requested project ———
    if requested_project_id not in allowed_projects:
        return build_response(error="Project not assigned or authorized", status=403, event=event)

    # ——— Task policy check ———
    task_scope = get_allowed_record_ids(current_user_id, "TimeEntries", "tasks_view")
    task_scopes = task_scope.get("scopes", [])
    task_all = task_scope.get("all", False)
    task_selected = task_scope.get("ids") or []

    if "none" in task_scopes:
        return build_response(error="Not authorized for tasks_view", status=403, event=event)

    # ——— Fetch active tasks for requested project (via ProjectIndex GSI) ———
    tasks = TASKS_TABLE.query(
        IndexName="ProjectIndex",
        KeyConditionExpression=Key("projectID").eq(requested_project_id),
        FilterExpression=Attr("status").eq("Active"),
        ProjectionExpression="taskID,taskName,assignedTo"
    ).get("Items", [])

    # ——— Filter tasks by policy ———
    tasks_payload = []
    for t in tasks:
        tid, tname, assigned = t.get("taskID"), t.get("taskName", "General"), t.get("assignedTo")

        # Case 1: Unassigned tasks → visible if any positive scope applies
        if not assigned:
            if task_all or "self" in task_scopes or "selected" in task_scopes:
                tasks_payload.append({"taskID": tid, "taskName": tname, "assignedTo": None})

        # Case 2: Assigned tasks → must belong to target user
        else:
            if assigned != target_user_id:
                continue
            if task_all:
                tasks_payload.append({"taskID": tid, "taskName": tname, "assignedTo": assigned})
            elif "self" in task_scopes and target_user_id == current_user_id:
                tasks_payload.append({"taskID": tid, "taskName": tname, "assignedTo": assigned})
            elif "selected" in task_scopes and tid in task_selected:
                tasks_payload.append({"taskID": tid, "taskName": tname, "assignedTo": assigned})

    # ——— Explicit error if no tasks matched ———
    if not tasks_payload:
        return build_response(error="No authorized tasks available for this project", status=403, event=event)

    return build_response(data={"tasks": tasks_payload}, status=200, event=event)





        










def handle_delete_entries(event, body, auth):
    """
    Delete selected time entries with policy_engine enforcement and cleanup.

    Rules enforced by policy_engine:
      - Must have TimeEntries.view for each entry.
      - Must have TimeEntries.delete for each entry.
      - Approved entries cannot be deleted.
      - Cleans up attached description files from S3.
      - Removes only PENDING approvals.
    """

    current_user_id = auth.get("user_id")

    entry_ids = body.get("timeentryIDs") or []
    if not isinstance(entry_ids, list) or not entry_ids:
        return build_response(status=400, error="timeentryIDs must be a non-empty list", event=event)

    deleted_count, deleted_approvals = 0, 0
    s3_delete_targets, approval_delete_keys = [], []

    # --- Load policy scopes once ---
    view_scope = get_allowed_record_ids(current_user_id, "TimeEntries", "records_view")
    delete_scope = get_allowed_record_ids(current_user_id, "TimeEntries", "records_delete")

    for eid in entry_ids:
        resp = ENTRIES_TABLE.get_item(Key={"TimeEntryID": eid})
        entry = resp.get("Item")
        if not entry:
            return build_response(status=404, error=f"Entry not found: {eid}", event=event)

        # --- Approved entries cannot be deleted
        if entry.get("isApproved"):
            return build_response(status=403, error=f"Cannot delete approved entry: {eid}", event=event)

        target_user_id = entry.get("UserID")

        # --- Policy check: must be able to VIEW this entry ---
        if not (
            view_scope["all"]
            or "all" in view_scope["scopes"]
            or ("self" in view_scope["scopes"] and current_user_id == target_user_id)
            or ("selected" in view_scope["scopes"] and target_user_id in (view_scope.get("ids") or []))
        ):
            return build_response(status=403, error=f"Not authorized to view entry {eid}", event=event)

        # --- Policy check: must be able to DELETE this entry ---
        if not (
            delete_scope["all"]
            or "all" in delete_scope["scopes"]
            or ("self" in delete_scope["scopes"] and current_user_id == target_user_id)
            or ("selected" in delete_scope["scopes"] and target_user_id in (delete_scope.get("ids") or []))
        ):
            return build_response(status=403, error=f"Not authorized to delete entry {eid}", event=event)

        # --- Queue S3 cleanup
        if entry.get("descriptionFileURL"):
            s3_delete_targets.append(entry["descriptionFileURL"])

        # --- Delete entry
        ENTRIES_TABLE.delete_item(Key={"TimeEntryID": eid})
        deleted_count += 1

        # --- Collect pending approvals
        appr_resp = APPROVAL_TABLE.query(
            IndexName="TimeEntryID-index",
            KeyConditionExpression=Key("TimeEntryID").eq(eid),
            ProjectionExpression="ApprovalID, ApprovalStatus, ManagerID"
        )
        for ap in appr_resp.get("Items", []) or []:
            if ap.get("ApprovalStatus") == "Pending":
                approval_delete_keys.append(
                    {"ApprovalID": ap["ApprovalID"], "ManagerID": ap.get("ManagerID", "n/A")}
                )

    # --- Delete approvals one by one ---
    for key in approval_delete_keys:
        try:
            APPROVAL_TABLE.delete_item(Key=key)
            deleted_approvals += 1
        except Exception as e:
            print(f"[Approval Delete] Failed for {key}: {e}")

    # --- S3 cleanup ---
    def safe_delete_s3(file_url: str):
        try:
            prefix = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/"
            if file_url.startswith(prefix):
                key = urllib.parse.unquote(file_url[len(prefix):])
                if key:
                    s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=key)
                    print(f"[S3] Deleted {key}")
        except Exception as e:
            print(f"[S3] Delete failed for {file_url}: {e}")

    for url in s3_delete_targets:
        safe_delete_s3(url)

    return build_response(
        status=200,
        data={"message": f"{deleted_count} entries deleted", "approvals_removed": deleted_approvals},
        event=event
    )
