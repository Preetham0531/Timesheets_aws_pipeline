# Data access layer for approval records
import boto3
import os
import logging
from typing import List, Dict, Any, Optional
from boto3.dynamodb.conditions import Key

logger = logging.getLogger("approval_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class ApprovalModel:
    """Data access layer for approval records"""
    
    def __init__(self):
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(os.environ['APPROVALS_TABLE'])

    def create_approval(self, approval_data: Dict[str, Any]) -> None:
        """Create a new approval record"""
        try:
            self.table.put_item(Item=approval_data)
            logger.debug(f"Created approval record: {approval_data.get('ApprovalID')}")
        except Exception as e:
            logger.error(f"Error creating approval record: {e}")
            raise

    def get_approval_by_id(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Get approval record by ID using GSI"""
        try:
            response = self.table.query(
                IndexName="ApprovalID-index",
                KeyConditionExpression=Key("ApprovalID").eq(approval_id),
                Limit=1
            )
            items = response.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error(f"Error getting approval by ID {approval_id}: {e}")
            raise

    def get_approvals_by_time_entry(self, time_entry_id: str) -> List[Dict[str, Any]]:
        """Get all approvals for a time entry"""
        try:
            response = self.table.query(
                IndexName="TimeEntryID-index",
                KeyConditionExpression=Key("TimeEntryID").eq(time_entry_id)
            )
            return response.get("Items", [])
        except Exception as e:
            logger.error(f"Error getting approvals by time entry {time_entry_id}: {e}")
            raise

    def get_approvals_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Get all approvals by status"""
        try:
            response = self.table.query(
                IndexName="ApprovalStatus-index",
                KeyConditionExpression=Key("ApprovalStatus").eq(status),
                ProjectionExpression="ApprovalID,ApprovalStatus,ApprovedAt,projectID,UserID,TimeEntryID"
            )
            return response.get("Items", [])
        except Exception as e:
            logger.error(f"Error getting approvals by status {status}: {e}")
            raise

    def update_approval_status(self, approval_id: str, manager_id: str, status: str, 
                              comments: str, approved_at: str, approved_by: str) -> None:
        """Update approval status"""
        try:
            self.table.update_item(
                Key={"ApprovalID": approval_id, "ManagerID": manager_id},
                UpdateExpression="SET ApprovalStatus = :s, Comments = :c, ApprovedAt = :a, ApprovedBy = :u",
                ExpressionAttributeValues={
                    ":s": status,
                    ":c": comments,
                    ":a": approved_at,
                    ":u": approved_by
                }
            )
            logger.debug(f"Updated approval status for {approval_id}")
        except Exception as e:
            logger.error(f"Error updating approval status for {approval_id}: {e}")
            raise

logger.info("✅ Approval model initialized")