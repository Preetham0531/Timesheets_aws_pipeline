# Data access layer for time entry records
import boto3
import os
import logging
from typing import Dict, Any, Optional
from boto3.dynamodb.conditions import Key

logger = logging.getLogger("time_entry_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class TimeEntryModel:
    """Data access layer for time entry records"""
    
    def __init__(self):
        dynamodb = boto3.resource("dynamodb")
        self.table = dynamodb.Table(os.environ['TIME_ENTRIES_TABLE'])

    def get_by_time_entry_id(self, time_entry_id: str) -> Optional[Dict[str, Any]]:
        """Get first time entry by TimeEntryID"""
        try:
            response = self.table.query(
                IndexName="TimeEntryID-index",
                KeyConditionExpression=Key("TimeEntryID").eq(time_entry_id)
            )
            items = response.get("Items", [])
            if not items:
                return None
            
            # Prefer daily entries
            for item in items:
                entry_type = str(item.get("EntryType") or item.get("entryType") or "").strip().lower()
                if entry_type in ("daily", "day"):
                    return item
            
            # Return first item if no daily entry found
            return items[0]
            
        except Exception as e:
            logger.error(f"Error getting time entry by ID {time_entry_id}: {e}")
            return None

    def update_approval_status(self, time_entry_id: str, is_approved: bool, status: str, 
                              approved_at: str, approved_by: str) -> None:
        """Update approval status for time entry"""
        try:
            self.table.update_item(
                Key={"TimeEntryID": time_entry_id},
                UpdateExpression="SET isApproved = :app, #st = :s, ApprovedAt = :a, ApprovedBy = :u",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={
                    ":app": is_approved,
                    ":s": status,
                    ":a": approved_at,
                    ":u": approved_by
                }
            )
            logger.debug(f"Updated time entry approval status for {time_entry_id}")
        except Exception as e:
            logger.error(f"Error updating time entry approval status for {time_entry_id}: {e}")
            raise

logger.info("✅ Time entry model initialized")