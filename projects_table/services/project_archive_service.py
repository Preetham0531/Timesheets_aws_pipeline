# -------------------- PROJECT ARCHIVE SERVICE --------------------
import os
from datetime import datetime, timedelta, timezone
from boto3.dynamodb.conditions import Key
from typing import List, Dict, Any

from models.database_models import (
    PROJECTS_TABLE, ASSIGNMENTS_TABLE, TASKS_TABLE, 
    ENTRIES_TABLE, APPROVALS_TABLE
)
from services.policy_service import policy_service
from utils.logging_helpers import get_logger

logger = get_logger(__name__)

# Config
ARCHIVE_TTL_DAYS = int(os.environ.get("ARCHIVE_TTL_DAYS", "30"))

class ProjectArchiveService:
    """Service for project archiving operations"""
    
    @staticmethod
    def query_items(table, index, project_id):
        """Query items by project ID from specified table and index"""
        return table.query(
            IndexName=index,
            KeyConditionExpression=Key("projectID").eq(project_id)
        ).get("Items", [])

    @staticmethod
    def archive_items(table, key_name, items, status_attr):
        """Archive items: set status + TTL (days)"""
        ttl_value = int((datetime.now(timezone.utc) + timedelta(days=ARCHIVE_TTL_DAYS)).timestamp())
        for item in items:
            key = {key_name: item[key_name]} if isinstance(key_name, str) else {k: item[k] for k in key_name}
            table.update_item(
                Key=key,
                UpdateExpression="SET #s = :archived, #exp = :exp",
                ExpressionAttributeNames={"#s": status_attr, "#exp": "expiresAt"},
                ExpressionAttributeValues={":archived": "Archive", ":exp": ttl_value}
            )

    @staticmethod
    def unarchive_items(table, key_name, items, status_attr):
        """Unarchive items: reset status + remove TTL"""
        for item in items:
            key = {key_name: item[key_name]} if isinstance(key_name, str) else {k: item[k] for k in key_name}
            table.update_item(
                Key=key,
                UpdateExpression="SET #s = :active REMOVE #exp",
                ExpressionAttributeNames={"#s": status_attr, "#exp": "expiresAt"},
                ExpressionAttributeValues={":active": "Active"}
            )

    @staticmethod
    def delete_items(table, key_name, items):
        """Delete items permanently"""
        for item in items:
            key = {key_name: item[key_name]} if isinstance(key_name, str) else {k: item[k] for k in key_name}
            table.delete_item(Key=key)

    @staticmethod
    def get_project_actions():
        """Get project-specific actions"""
        return {
            "archive": lambda pid: PROJECTS_TABLE.update_item(
                Key={"projectID": pid},
                UpdateExpression="SET #s = :archived, #exp = :exp",
                ExpressionAttributeNames={"#s": "status", "#exp": "expiresAt"},
                ExpressionAttributeValues={
                    ":archived": "Archive",
                    ":exp": int((datetime.now(timezone.utc) + timedelta(days=ARCHIVE_TTL_DAYS)).timestamp())
                }
            ),
            "unarchive": lambda pid: PROJECTS_TABLE.update_item(
                Key={"projectID": pid},
                UpdateExpression="SET #s = :active REMOVE #exp",
                ExpressionAttributeNames={"#s": "status", "#exp": "expiresAt"},
                ExpressionAttributeValues={":active": "Active"}
            ),
            "delete": lambda pid: PROJECTS_TABLE.delete_item(Key={"projectID": pid}),
        }

    @classmethod
    def get_assignment_actions(cls):
        """Get assignment-specific actions"""
        return {
            "archive": lambda pid: cls.archive_items(
                ASSIGNMENTS_TABLE, "assignmentID",
                cls.query_items(ASSIGNMENTS_TABLE, "ProjectAssignments-index", pid),
                "status"
            ),
            "unarchive": lambda pid: cls.unarchive_items(
                ASSIGNMENTS_TABLE, "assignmentID",
                cls.query_items(ASSIGNMENTS_TABLE, "ProjectAssignments-index", pid),
                "status"
            ),
            "delete": lambda pid: cls.delete_items(
                ASSIGNMENTS_TABLE, "assignmentID",
                cls.query_items(ASSIGNMENTS_TABLE, "ProjectAssignments-index", pid)
            ),
        }

    @classmethod
    def get_task_actions(cls):
        """Get task-specific actions"""
        return {
            "archive": lambda pid: cls.archive_items(
                TASKS_TABLE, "taskID",
                cls.query_items(TASKS_TABLE, "ProjectIndex", pid),
                "status"
            ),
            "unarchive": lambda pid: cls.unarchive_items(
                TASKS_TABLE, "taskID",
                cls.query_items(TASKS_TABLE, "ProjectIndex", pid),
                "status"
            ),
            "delete": lambda pid: cls.delete_items(
                TASKS_TABLE, "taskID",
                cls.query_items(TASKS_TABLE, "ProjectIndex", pid)
            ),
        }

    @classmethod
    def get_entry_actions(cls):
        """Get time entry-specific actions"""
        return {
            "archive": lambda pid: cls.archive_items(
                ENTRIES_TABLE, "TimeEntryID",
                cls.query_items(ENTRIES_TABLE, "ProjectDate-index", pid),
                "projectstatus"
            ),
            "unarchive": lambda pid: cls.unarchive_items(
                ENTRIES_TABLE, "TimeEntryID",
                cls.query_items(ENTRIES_TABLE, "ProjectDate-index", pid),
                "projectstatus"
            ),
            "delete": lambda pid: cls.delete_items(
                ENTRIES_TABLE, "TimeEntryID",
                cls.query_items(ENTRIES_TABLE, "ProjectDate-index", pid)
            ),
        }

    @classmethod
    def get_approval_actions(cls):
        """Get approval-specific actions"""
        return {
            "archive": lambda pid: cls.archive_items(
                APPROVALS_TABLE, ["ApprovalID", "ManagerID"],
                cls.query_items(APPROVALS_TABLE, "ProjectIndex", pid),
                "projectstatus"
            ),
            "unarchive": lambda pid: cls.unarchive_items(
                APPROVALS_TABLE, ["ApprovalID", "ManagerID"],
                cls.query_items(APPROVALS_TABLE, "ProjectIndex", pid),
                "projectstatus"
            ),
            "delete": lambda pid: cls.delete_items(
                APPROVALS_TABLE, ["ApprovalID", "ManagerID"],
                cls.query_items(APPROVALS_TABLE, "ProjectIndex", pid)
            ),
        }

    @classmethod
    def get_entity_actions(cls):
        """Get all entity actions"""
        return {
            "project": cls.get_project_actions(),
            "assignment": cls.get_assignment_actions(),
            "task": cls.get_task_actions(),
            "entry": cls.get_entry_actions(),
            "approval": cls.get_approval_actions(),
        }

    @classmethod
    def process_project_archive_action(cls, project_ids: List[str], action: str, user_id: str) -> Dict[str, Any]:
        """Process archive/unarchive/delete action on projects"""
        if action not in ["archive", "unarchive", "delete"]:
            raise ValueError("Invalid action. Use archive, unarchive, or delete.")
        
        processed_count = 0
        entity_actions = cls.get_entity_actions()
        
        # Permission mapping
        perm_map = {
            "archive": "archive",
            "unarchive": "unarchive", 
            "delete": "delete"
        }
        policy_action = perm_map[action]
        
        for pid in project_ids:
            # Check if project exists
            project = PROJECTS_TABLE.get_item(Key={"projectID": pid}).get("Item")
            if not project:
                raise ValueError(f"Project {pid} not found")

            # Check permissions
            allowed = policy_service.can_do(user_id, "Projects", policy_action, record_id=pid)
            if not allowed:
                raise PermissionError(f"Forbidden: missing permission to {action} project {pid}")

            # Execute entity actions
            for entity, actions in entity_actions.items():
                actions[action](pid)

            processed_count += 1

        return {
            "message": f"{action.capitalize()}d {processed_count} project(s) successfully",
            "processed_count": processed_count,
            "action": action
        }

    @staticmethod
    def handle_archive_project_request(request_body, requesting_user_id, requesting_user_role):
        """Handle complete archive project request - moved from handler"""
        project_id = request_body.get("projectID")
        if not project_id:
            raise ValueError("projectID is required")
        
        result = ProjectArchiveService.archive_project(project_id, requesting_user_id)
        
        return {
            "status": 200,
            "data": {
                "message": "Project archived successfully",
                "projectID": project_id,
                "archivedAt": result.get("archivedAt"),
                "archivedBy": requesting_user_id
            }
        }

    @staticmethod
    def handle_unarchive_project_request(request_body, requesting_user_id, requesting_user_role):
        """Handle complete unarchive project request - moved from handler"""
        project_id = request_body.get("projectID")
        if not project_id:
            raise ValueError("projectID is required")
        
        result = ProjectArchiveService.unarchive_project(project_id, requesting_user_id)
        
        return {
            "status": 200,
            "data": {
                "message": "Project unarchived successfully",
                "projectID": project_id,
                "unarchivedAt": result.get("unarchivedAt"),
                "unarchivedBy": requesting_user_id
            }
        }