# Data access layer for project assignment records
import boto3
import os
import logging
from typing import List
from boto3.dynamodb.conditions import Key

logger = logging.getLogger("assignment_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class AssignmentModel:
    """Data access layer for project assignment records"""
    
    def __init__(self):
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(os.environ['PROJECT_ASSIGNMENTS_TABLE'])

    def get_users_for_project(self, project_id: str) -> List[str]:
        """Get list of user IDs assigned to a project"""
        try:
            response = self.table.query(
                IndexName="ProjectAssignments-index",
                KeyConditionExpression=Key("projectID").eq(project_id)
            )
            return [item["userID"] for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error getting project assigned users for {project_id}: {e}")
            return []

    def get_projects_for_user(self, user_id: str) -> List[str]:
        """Get list of project IDs that user is assigned to"""
        try:
            response = self.table.query(
                IndexName="GSI_UserID",
                KeyConditionExpression=Key("userID").eq(user_id)
            )
            return [item["projectID"] for item in response.get("Items", [])]
        except Exception as e:
            logger.error(f"Error getting user project assignments for {user_id}: {e}")
            return []

logger.info("✅ Assignment model initialized")