"""
User assignment repository for database operations on user grants.
"""
from typing import Any, Dict, List, Optional, Tuple
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from logging_config import create_logger
from .database import GRANTS_TBL
from config import TABLE_CONFIG

logger = create_logger("models.assignment_repository")


def load_user_assignments(user_id: str) -> List[Dict[str, Any]]:
    """Load all assignments for a user."""
    try:
        resp = GRANTS_TBL.query(KeyConditionExpression=Key("userID").eq(user_id))
        return resp.get("Items", []) or []
    except Exception as e:
        logger.error(f"Error loading user assignments for {user_id}: {e}")
        return []


def list_users_by_role(role_name: str, limit: int = 50, 
                       next_token: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """List users assigned to a specific role."""
    query_kwargs = {
        "IndexName": TABLE_CONFIG["grants_role_index"],
        "KeyConditionExpression": Key("role").eq(role_name),
        "Limit": limit
    }
    if next_token:
        query_kwargs["ExclusiveStartKey"] = next_token
    
    try:
        resp = GRANTS_TBL.query(**query_kwargs)
        grants = resp.get("Items", []) or []
        lek = resp.get("LastEvaluatedKey")
    except ClientError as e:
        msg = (e.response.get("Error", {}) or {}).get("Message", str(e))
        if "does not have the specified index" in msg or "backfilling" in msg.lower():
            scan_kwargs = {"Limit": limit, "FilterExpression": Attr("role").eq(role_name)}
            if next_token:
                scan_kwargs["ExclusiveStartKey"] = next_token
            resp = GRANTS_TBL.scan(**scan_kwargs)
            grants = resp.get("Items", []) or []
            lek = resp.get("LastEvaluatedKey")
        else:
            raise
    
    return grants, lek


def validate_target_user(user_id: str) -> bool:
    """Validate if a target user exists in the grants table."""
    if not user_id:
        return False
    try:
        resp = GRANTS_TBL.query(KeyConditionExpression=Key("userID").eq(user_id), Limit=1)
        return len(resp.get("Items", []) or []) > 0
    except Exception as e:
        logger.error(f"Error validating target user {user_id}: {str(e)}")
        return False
