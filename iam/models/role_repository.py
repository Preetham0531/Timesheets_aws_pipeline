"""
Role repository for database operations on roles.
"""
from typing import Any, Dict, List, Optional
from boto3.dynamodb.conditions import Key
from logging_config import create_logger
from .database import ROLES_TBL
from config import TABLE_CONFIG, BATCH_SIZE

logger = create_logger("models.role_repository")


def scan_all_roles() -> List[Dict[str, Any]]:
    """Scan all roles from the database."""
    items: List[Dict[str, Any]] = []
    resp = ROLES_TBL.scan()
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = ROLES_TBL.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        items.extend(resp.get("Items", []))
    return items


def load_role_by_rid(rid: str) -> Optional[Dict[str, Any]]:
    """Load a role by its RID."""
    q = ROLES_TBL.query(KeyConditionExpression=Key("rid").eq(rid), Limit=1)
    return (q.get("Items") or [None])[0]


def load_role_by_name(role_name: str) -> Optional[Dict[str, Any]]:
    """Load a role by its name using GSI."""
    q = ROLES_TBL.query(
        IndexName=TABLE_CONFIG["role_index"],
        KeyConditionExpression=Key("role").eq(role_name),
        Limit=1
    )
    return (q.get("Items") or [None])[0]


def batch_get_roles_by_ids(rids: List[str]) -> List[Dict[str, Any]]:
    """Fetch role records by list of rid values."""
    if not rids:
        return []
    
    all_items: List[Dict[str, Any]] = []
    
    for i in range(0, len(rids), BATCH_SIZE):
        chunk = rids[i:i+BATCH_SIZE]
        try:
            for rid in chunk:
                resp = ROLES_TBL.query(
                    IndexName="rid-index",
                    KeyConditionExpression=Key("rid").eq(rid)
                )
                items = resp.get("Items", [])
                all_items.extend(items)
        except Exception as e:
            logger.error(f"Error fetching roles for rids={chunk}: {e}")
    
    return all_items


def role_exists(role_name: str) -> bool:
    """Check if a role exists by name."""
    resp = ROLES_TBL.query(
        IndexName=TABLE_CONFIG["role_index"],
        KeyConditionExpression=Key("role").eq(role_name)
    )
    return bool(resp.get("Items"))
