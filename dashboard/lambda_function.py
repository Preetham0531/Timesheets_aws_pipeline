

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from boto3.dynamodb.conditions import Attr, Key
import boto3
from utils import get_cors_headers, build_response

# ========== POLICY ENGINE INTEGRATION ==========
try:
    from policy_engine import (
        can_do,
        get_allowed_record_ids,
        can_access_record,
        get_accessible_records_filter,
        _load_user_assignments
    )
    POLICY_ENGINE_AVAILABLE = True
    print("✅ Policy engine imported successfully for Dashboard")
except ImportError as e:
    print(f"❌ Policy engine import failed: {e}")
    POLICY_ENGINE_AVAILABLE = False
    
    # Fallback functions
    def can_do(user_id: str, module: str, action: str, **kwargs) -> bool:
        return True
    
    def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}
    
    def can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
        return True
    
    def get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"type": "all", "scopes": ["fallback"], "pattern": "all"}

# ========= LOGGING =========
logger = logging.getLogger("dashboard_handler")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ========= AWS RESOURCES =========
region = "ap-south-1"
dynamodb = boto3.resource("dynamodb", region_name=region)
client = boto3.client("dynamodb", region_name=region)

# Table references
TIME_ENTRIES = dynamodb.Table("dev.TimeEntries.ddb-table")
PROJECTS = dynamodb.Table("dev.Projects.ddb-table")
TASKS = dynamodb.Table("dev.Tasks.ddb-table")
APPROVALS = dynamodb.Table("dev.Approvals.ddb-table")
ASSIGNMENTS = dynamodb.Table("dev.ProjectAssignments.ddb-table")
USERS = dynamodb.Table("dev.Users.ddb-table")

# ========= UTILITY FUNCTIONS =========

def format_time_ago(iso_ts: str) -> str:
    """Format timestamp as human-readable time ago"""
    try:
        t = datetime.fromisoformat(iso_ts.replace('Z', '+00:00'))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - t
        
        if delta.days > 0:
            return f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
        hrs = delta.seconds // 3600
        if hrs > 0:
            return f"{hrs} hour{'s' if hrs > 1 else ''} ago"
        mins = (delta.seconds % 3600) // 60
        if mins > 0:
            return f"{mins} minute{'s' if mins > 1 else ''} ago"
        return "just now"
    except Exception as e:
        logger.warning(f"Error formatting time: {e}")
        return "unknown"

def get_user_full_name(userID: str) -> str:
    """Get user's full name from Users table"""
    try:
        item = USERS.get_item(Key={"userID": userID}).get("Item", {})
        first = item.get("firstName", "").strip()
        last = item.get("lastName", "").strip()
        full_name = f"{first} {last}".strip()
        return full_name if full_name else f"User {userID[:8]}"
    except Exception as e:
        logger.warning(f"Error getting user name for {userID}: {e}")
        return f"User {userID[:8]}"

def check_dashboard_access(user_id: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Check user's dashboard access permissions using policy engine
    Returns: (has_access, access_level, access_details)
    """
    try:
        logger.info(f"🔍 Checking dashboard access for user {user_id}")
        
        if not POLICY_ENGINE_AVAILABLE:
            logger.warning("⚠️ Policy engine not available, allowing access")
            return True, "all", {"pattern": "fallback", "reason": "policy_engine_unavailable"}
        
        # Check if user has any dashboard view access
        if not can_do(user_id, "Dashboard", "view"):
            logger.warning(f"❌ User {user_id} has no dashboard view access")
            return False, "none", {"pattern": "denied", "reason": "no_dashboard_access"}
        
        # Get detailed access information
        access_filter = get_accessible_records_filter(user_id, "Dashboard", "view")
        access_scope = get_allowed_record_ids(user_id, "Dashboard", "view")
        
        filter_type = access_filter.get("type", "none")
        pattern = access_scope.get("pattern", "unknown")
        scopes = access_scope.get("scopes", [])
        
        logger.info(f"✅ Dashboard access granted: type={filter_type}, pattern={pattern}, scopes={scopes}")
        
        # Determine access level
        if access_scope.get("all", False) or "all" in scopes:
            access_level = "all"
        elif "self" in scopes:
            access_level = "self"
        elif "selected" in scopes:
            access_level = "selected"
        else:
            access_level = "limited"
        
        access_details = {
            "pattern": pattern,
            "scopes": scopes,
            "filter_type": filter_type,
            "allowed_ids": access_scope.get("ids", []),
            "denied_ids": access_scope.get("denied_ids", [])
        }
        
        return True, access_level, access_details
        
    except Exception as e:
        logger.error(f"❌ Error checking dashboard access: {e}")
        # Fail secure - deny access on error
        return False, "none", {"pattern": "error", "reason": str(e)}

def get_accessible_projects(user_id: str, access_level: str, access_details: Dict[str, Any]) -> List[str]:
    """Get list of project IDs user can access based on their dashboard permissions"""
    try:
        logger.info(f"🔍 Getting accessible projects for user {user_id}, access_level={access_level}")
        
        if access_level == "all":
            # User can see all projects
            proj_resp = PROJECTS.query(
                IndexName="GSI_Status",
                KeyConditionExpression=Key("status").eq("Active")
            )
            project_ids = [p["projectID"] for p in proj_resp.get("Items", [])]
            logger.info(f"✅ All access: {len(project_ids)} projects")
            return project_ids
            
        elif access_level == "self":
            # User can only see projects they're assigned to
            assign_resp = ASSIGNMENTS.query(
                IndexName="UserAssignments-index",
                KeyConditionExpression=Key("userID").eq(user_id),
                FilterExpression=Attr("status").eq("Active"),
                ProjectionExpression="projectID"
            )
            project_ids = [i["projectID"] for i in assign_resp.get("Items", [])]
            logger.info(f"✅ Self access: {len(project_ids)} assigned projects")
            return project_ids
            
        elif access_level == "selected":
            # User can see specific projects based on policy
            allowed_ids = access_details.get("allowed_ids", [])
            if allowed_ids:
                # Filter to only active projects that user has access to
                proj_resp = PROJECTS.query(
                    IndexName="GSI_Status",
                    KeyConditionExpression=Key("status").eq("Active")
                )
                all_active_projects = {p["projectID"] for p in proj_resp.get("Items", [])}
                project_ids = [pid for pid in allowed_ids if pid in all_active_projects]
                logger.info(f"✅ Selected access: {len(project_ids)} allowed projects")
                return project_ids
            else:
                # Fallback to user's assigned projects
                assign_resp = ASSIGNMENTS.query(
                    IndexName="UserAssignments-index",
                    KeyConditionExpression=Key("userID").eq(user_id),
                    FilterExpression=Attr("status").eq("Active"),
                    ProjectionExpression="projectID"
                )
                project_ids = [i["projectID"] for i in assign_resp.get("Items", [])]
                logger.info(f"✅ Selected access (fallback): {len(project_ids)} assigned projects")
                return project_ids
                
        else:
            # Limited or no access
            logger.warning(f"⚠️ Limited access level: {access_level}")
            return []
            
    except Exception as e:
        logger.error(f"❌ Error getting accessible projects: {e}")
        return []

def get_accessible_users(user_id: str, access_level: str, project_ids: List[str]) -> List[str]:
    """Get list of user IDs that the current user can see data for"""
    try:
        if access_level == "all":
            # Admin can see all users - get from active project assignments
            user_ids = set()
            for pid in project_ids:
                assign_resp = ASSIGNMENTS.query(
                    IndexName="ProjectAssignments-index",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Active"),
                    ProjectionExpression="userID"
                )
                for assignment in assign_resp.get("Items", []):
                    user_ids.add(assignment["userID"])
            
            logger.info(f"✅ All access: can see {len(user_ids)} users")
            return list(user_ids)
            
        elif access_level == "selected":
            # Can see team members in accessible projects
            user_ids = set()
            for pid in project_ids:
                assign_resp = ASSIGNMENTS.query(
                    IndexName="ProjectAssignments-index",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Active"),
                    ProjectionExpression="userID"
                )
                for assignment in assign_resp.get("Items", []):
                    user_ids.add(assignment["userID"])
            
            logger.info(f"✅ Selected access: can see {len(user_ids)} team members")
            return list(user_ids)
            
        else:
            # Self access - can only see own data
            logger.info(f"✅ Self access: can only see own data")
            return [user_id]
            
    except Exception as e:
        logger.error(f"❌ Error getting accessible users: {e}")
        return [user_id]  # Fallback to self only

def get_recent_activity(user_id: str, access_level: str, project_ids: List[str], 
                       accessible_users: List[str], start_date: str, end_date: str) -> List[Dict[str, Any]]:
    """Get recent activity based on user's access permissions"""
    try:
        logger.info(f"🔍 Getting recent activity: access_level={access_level}, projects={len(project_ids)}, users={len(accessible_users)}")
        raw = []

        # 1) Recent time entries
        if access_level == "all":
            # Admin can see all time entries in accessible projects
            for pid in project_ids[:10]:  # Limit to prevent too many queries
                resp = TIME_ENTRIES.query(
                    IndexName="ProjectDate-index",
                    KeyConditionExpression=Key("projectID").eq(pid) & 
                                           Key("Date").between(start_date, end_date),
                    ScanIndexForward=False,
                    Limit=3
                )
                for item in resp.get("Items", []):
                    if item.get("Date"):
                        raw.append({
                            "type": "timeEntry",
                            "timestamp": item.get("Date"),
                            "userID": item.get("UserID"),
                            "taskName": item.get("Task"),
                            "projectID": pid
                        })
        else:
            # Non-admin sees own time entries and team members if selected access
            target_users = accessible_users if access_level == "selected" else [user_id]
            for target_user in target_users[:10]:  # Limit users
                resp = TIME_ENTRIES.query(
                    IndexName="UserDate-index",
                    KeyConditionExpression=Key("UserID").eq(target_user) & 
                                           Key("Date").between(start_date, end_date),
                    ScanIndexForward=False,
                    Limit=3
                )
                for item in resp.get("Items", []):
                    if item.get("Date") and item.get("projectID") in project_ids:
                        raw.append({
                            "type": "timeEntry",
                            "timestamp": item.get("Date"),
                            "userID": target_user,
                            "taskName": item.get("Task"),
                            "projectID": item.get("projectID")
                        })

        # 2) Recent task completions
        for pid in project_ids[:10]:  # Limit projects
            if access_level == "all":
                # Admin sees all completed tasks
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Completed") & 
                                     Attr("assignedAt").between(start_date, end_date),
                    ScanIndexForward=False,
                    Limit=2
                )
            else:
                # Non-admin sees tasks assigned to accessible users
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Completed") & 
                                     Attr("assignedAt").between(start_date, end_date) &
                                     Attr("assignedTo").is_in(accessible_users),
                    ScanIndexForward=False,
                    Limit=2
                )
            
            for task in task_resp.get("Items", []):
                if task.get("assignedAt"):
                    raw.append({
                        "type": "task",
                        "timestamp": task.get("assignedAt"),
                        "userID": task.get("assignedTo", "system"),
                        "taskName": task.get("taskName"),
                        "projectID": pid
                    })

        # 3) Recent pending approvals
        if access_level == "all":
            # Admin sees all pending approvals
            approval_resp = APPROVALS.query(
                IndexName="GSI_ApprovalStatus",
                KeyConditionExpression=Key("ApprovalStatus").eq("Pending"),
                ScanIndexForward=False,
                Limit=5
            )
            approvals = approval_resp.get("Items", [])
        else:
            # Non-admin sees approvals from accessible users
            approvals = []
            for target_user in accessible_users[:5]:  # Limit users
                approval_resp = APPROVALS.query(
                    IndexName="GSI_RequestorStatus",
                    KeyConditionExpression=Key("RequestRaisedBy").eq(target_user) & 
                                           Key("ApprovalStatus").eq("Pending"),
                    ScanIndexForward=False,
                    Limit=2
                )
                approvals.extend(approval_resp.get("Items", []))

        # Get task names for approvals
        task_map = {}
        time_entry_ids = {a.get("TimeEntryID") for a in approvals if a.get("TimeEntryID")}
        if time_entry_ids:
            keys = [{"TimeEntryID": {"S": tid}} for tid in time_entry_ids]
            try:
                batch = client.batch_get_item(RequestItems={
                    TIME_ENTRIES.name: {"Keys": keys, "ProjectionExpression": "TimeEntryID, Task"}
                })
                for item in batch["Responses"].get(TIME_ENTRIES.name, []):
                    task_map[item["TimeEntryID"]["S"]] = item.get("Task", {}).get("S", "Unknown Task")
            except Exception as e:
                logger.warning(f"Error getting task names for approvals: {e}")

        for approval in approvals:
            timestamp = approval.get("requestRaisedAt") or approval.get("ApprovalDate")
            if timestamp:
                raw.append({
                    "type": "approval",
                    "timestamp": timestamp,
                    "userID": approval.get("RequestRaisedBy"),
                    "taskName": task_map.get(approval.get("TimeEntryID"), "Unknown Task")
                })

        # 4) Sort and format recent activity
        recent_activities = []
        for entry in sorted(raw, key=lambda x: x["timestamp"], reverse=True)[:8]:
            user_name = get_user_full_name(entry["userID"])
            time_ago = format_time_ago(entry["timestamp"])

            if entry["type"] == "timeEntry":
                title = f"New timesheet: {entry.get('taskName', 'Unknown Task')}"
                icon = "clock"
            elif entry["type"] == "task":
                title = f"Task completed: {entry.get('taskName', 'Unknown Task')}"
                icon = "check-circle"
            else:  # approval
                title = f"Pending approval: {entry.get('taskName', 'Unknown Task')}"
                icon = "clock"

            recent_activities.append({
                "type": entry["type"],
                "title": title,
                "subtitle": f"{user_name} • {time_ago}",
                "icon": icon,
                "timestamp": entry["timestamp"],
                "userID": entry["userID"]
            })

        logger.info(f"✅ Generated {len(recent_activities)} recent activities")
        return recent_activities

    except Exception as e:
        logger.error(f"❌ Error getting recent activity: {e}")
        return []

def get_dashboard_metrics(user_id: str, access_level: str, project_ids: List[str], 
                         accessible_users: List[str], start_date: str, end_date: str) -> Dict[str, Any]:
    """Get dashboard metrics based on user's access permissions"""
    try:
        logger.info(f"🔍 Getting dashboard metrics: access_level={access_level}")
        
        metrics = {
            "activeProjectCount": len(project_ids),
            "totalTrackedHours": 0.0,
            "completedTaskCount": 0,
            "pendingApprovalCount": 0,
            "pendingTaskCount": 0,
            "teamMemberCount": len(accessible_users) if access_level != "self" else 1
        }

        # Calculate total tracked hours
        for pid in project_ids:
            if access_level == "all":
                # Admin sees all hours in project
                time_resp = TIME_ENTRIES.query(
                    IndexName="ProjectDate-index",
                    KeyConditionExpression=Key("projectID").eq(pid) & 
                                           Key("Date").between(start_date, end_date)
                )
            else:
                # Non-admin sees hours from accessible users only
                time_resp = TIME_ENTRIES.query(
                    IndexName="ProjectDate-index",
                    KeyConditionExpression=Key("projectID").eq(pid) & 
                                           Key("Date").between(start_date, end_date),
                    FilterExpression=Attr("UserID").is_in(accessible_users)
                )
            
            for entry in time_resp.get("Items", []):
                hours = float(entry.get("TotalHoursWorked", 0))
                metrics["totalTrackedHours"] += hours

        # Calculate completed tasks
        for pid in project_ids:
            if access_level == "all":
                # Admin sees all completed tasks
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Completed") & 
                                     Attr("assignedAt").between(start_date, end_date)
                )
            else:
                # Non-admin sees tasks assigned to accessible users
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").eq("Completed") & 
                                     Attr("assignedAt").between(start_date, end_date) &
                                     Attr("assignedTo").is_in(accessible_users)
                )
            
            metrics["completedTaskCount"] += task_resp.get("Count", 0)

        # Calculate pending approvals
        if access_level == "all":
            # Admin sees all pending approvals
            approval_resp = APPROVALS.query(
                IndexName="GSI_ApprovalStatus",
                KeyConditionExpression=Key("ApprovalStatus").eq("Pending")
            )
            metrics["pendingApprovalCount"] = approval_resp.get("Count", 0)
        else:
            # Non-admin sees approvals from accessible users
            total_pending = 0
            for target_user in accessible_users:
                approval_resp = APPROVALS.query(
                    IndexName="GSI_RequestorStatus",
                    KeyConditionExpression=Key("RequestRaisedBy").eq(target_user) & 
                                           Key("ApprovalStatus").eq("Pending")
                )
                total_pending += approval_resp.get("Count", 0)
            metrics["pendingApprovalCount"] = total_pending

        # Calculate pending tasks
        for pid in project_ids:
            if access_level == "all":
                # Admin sees all pending tasks
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").ne("Completed")
                )
            else:
                # Non-admin sees tasks assigned to accessible users
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").ne("Completed") &
                                     Attr("assignedTo").is_in(accessible_users)
                )
            
            metrics["pendingTaskCount"] += task_resp.get("Count", 0)

        # Round hours to 2 decimal places
        metrics["totalTrackedHours"] = round(metrics["totalTrackedHours"], 2)
        
        logger.info(f"✅ Generated metrics: {metrics}")
        return metrics

    except Exception as e:
        logger.error(f"❌ Error getting dashboard metrics: {e}")
        return {
            "activeProjectCount": 0,
            "totalTrackedHours": 0.0,
            "completedTaskCount": 0,
            "pendingApprovalCount": 0,
            "pendingTaskCount": 0,
            "teamMemberCount": 1,
            "error": str(e)
        }

def get_pending_items(user_id: str, access_level: str, project_ids: List[str], 
                     accessible_users: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Get pending approvals and tasks based on user's access permissions"""
    try:
        logger.info(f"🔍 Getting pending items: access_level={access_level}")
        
        pending_approvals = []
        pending_tasks = []

        # Get pending approvals
        if access_level == "all":
            # Admin sees all pending approvals
            approval_resp = APPROVALS.query(
                IndexName="GSI_ApprovalStatus",
                KeyConditionExpression=Key("ApprovalStatus").eq("Pending"),
                Limit=20
            )
            approvals = approval_resp.get("Items", [])
        else:
            # Non-admin sees approvals from accessible users
            approvals = []
            for target_user in accessible_users[:10]:  # Limit to prevent too many queries
                approval_resp = APPROVALS.query(
                    IndexName="GSI_RequestorStatus",
                    KeyConditionExpression=Key("RequestRaisedBy").eq(target_user) & 
                                           Key("ApprovalStatus").eq("Pending"),
                    Limit=5
                )
                approvals.extend(approval_resp.get("Items", []))

        # Get task names for approvals
        task_map = {}
        time_entry_ids = {a.get("TimeEntryID") for a in approvals if a.get("TimeEntryID")}
        if time_entry_ids:
            keys = [{"TimeEntryID": {"S": tid}} for tid in time_entry_ids]
            try:
                batch = client.batch_get_item(RequestItems={
                    TIME_ENTRIES.name: {"Keys": keys, "ProjectionExpression": "TimeEntryID, Task"}
                })
                for item in batch["Responses"].get(TIME_ENTRIES.name, []):
                    task_map[item["TimeEntryID"]["S"]] = item.get("Task", {}).get("S", "Unknown Task")
            except Exception as e:
                logger.warning(f"Error getting task names: {e}")

        # Format pending approvals
        for approval in approvals:
            pending_approvals.append({
                "approvalID": approval.get("ApprovalID"),
                "timeEntryID": approval.get("TimeEntryID"),
                "taskName": task_map.get(approval.get("TimeEntryID"), "Unknown Task"),
                "requestRaisedBy": approval.get("RequestRaisedBy"),
                "requestRaisedByName": get_user_full_name(approval.get("RequestRaisedBy", "")),
                "requestRaisedAt": approval.get("requestRaisedAt"),
                "approvalStatus": approval.get("ApprovalStatus"),
                "timeAgo": format_time_ago(approval.get("requestRaisedAt", ""))
            })

        # Get pending tasks
        for pid in project_ids:
            if access_level == "all":
                # Admin sees all pending tasks in project
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").ne("Completed"),
                    Limit=10
                )
            else:
                # Non-admin sees tasks assigned to accessible users or unassigned
                task_resp = TASKS.query(
                    IndexName="ProjectIndex",
                    KeyConditionExpression=Key("projectID").eq(pid),
                    FilterExpression=Attr("status").ne("Completed") & 
                                     (Attr("assignedTo").is_in(accessible_users) | 
                                      Attr("assignedTo").not_exists()),
                    Limit=5
                )
            
            for task in task_resp.get("Items", []):
                pending_tasks.append({
                    "taskID": task.get("taskID"),
                    "taskName": task.get("taskName"),
                    "projectID": pid,
                    "assignedTo": task.get("assignedTo"),
                    "assignedToName": get_user_full_name(task.get("assignedTo", "")) if task.get("assignedTo") else "Unassigned",
                    "assignedAt": task.get("assignedAt"),
                    "status": task.get("status"),
                    "priority": task.get("priority", "Medium"),
                    "timeAgo": format_time_ago(task.get("assignedAt", ""))
                })

        logger.info(f"✅ Found {len(pending_approvals)} pending approvals, {len(pending_tasks)} pending tasks")
        
        return {
            "pendingApprovals": pending_approvals[:15],  # Limit response size
            "pendingTasks": pending_tasks[:15]
        }

    except Exception as e:
        logger.error(f"❌ Error getting pending items: {e}")
        return {
            "pendingApprovals": [],
            "pendingTasks": []
        }

def lambda_handler(event, context):
    """Main dashboard handler with policy engine integration"""
    try:
        logger.info("🚀 Dashboard request started")
        
        # CORS preflight
        if event.get("httpMethod", "").upper() == "OPTIONS":
            return build_response(message="CORS OK", status=200, event=event)

        # Extract authentication context
        auth = event.get("requestContext", {}).get("authorizer", {})
        user_id = auth.get("user_id")
        
        if not user_id:
            logger.error("❌ Missing user_id in request")
            return build_response(error="Missing user authentication", status=401, event=event)

        logger.info(f"👤 Dashboard request from user: {user_id}")

        # Check dashboard access permissions
        has_access, access_level, access_details = check_dashboard_access(user_id)
        
        if not has_access:
            logger.warning(f"🚫 Dashboard access denied for user {user_id}")
            return build_response(
                error="Access denied: You don't have permission to view the dashboard",
                status=403,
                event=event
            )

        logger.info(f"✅ Dashboard access granted: level={access_level}")

        # Get date range parameters
        params = event.get("queryStringParameters") or {}
        start_date = params.get("startDate")
        end_date = params.get("endDate")
        
        if not start_date or not end_date:
            return build_response(
                error="Missing required parameters: startDate and endDate", 
                status=400, 
                event=event
            )

        # Get accessible projects based on permissions
        project_ids = get_accessible_projects(user_id, access_level, access_details)
        logger.info(f"📊 User can access {len(project_ids)} projects")

        # Get accessible users based on permissions
        accessible_users = get_accessible_users(user_id, access_level, project_ids)
        logger.info(f"👥 User can see data for {len(accessible_users)} users")

        # Generate dashboard data
        metrics = get_dashboard_metrics(user_id, access_level, project_ids, accessible_users, start_date, end_date)
        recent_activity = get_recent_activity(user_id, access_level, project_ids, accessible_users, start_date, end_date)
        pending_items = get_pending_items(user_id, access_level, project_ids, accessible_users)

        # Build comprehensive response
        dashboard_data = {
            "requestedBy": user_id,
            "requestedByName": get_user_full_name(user_id),
            "accessLevel": access_level,
            "dateRange": {
                "startDate": start_date,
                "endDate": end_date
            },
            "permissions": {
                "accessLevel": access_level,
                "pattern": access_details.get("pattern"),
                "scopes": access_details.get("scopes", []),
                "policyEngineEnabled": POLICY_ENGINE_AVAILABLE
            },
            **metrics,
            "recentActivity": recent_activity,
            **pending_items,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "accessibleProjects": len(project_ids),
                "accessibleUsers": len(accessible_users),
                "recentActivityCount": len(recent_activity),
                "pendingApprovalsCount": len(pending_items["pendingApprovals"]),
                "pendingTasksCount": len(pending_items["pendingTasks"])
            }
        }

        logger.info(f"✅ Dashboard generated successfully for user {user_id}")
        return build_response(data=dashboard_data, status=200, event=event)

    except Exception as e:
        logger.error(f"❌ Dashboard error: {e}")
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return build_response(
            error=f"Internal server error: {str(e)}", 
            status=500, 
            event=event
        )