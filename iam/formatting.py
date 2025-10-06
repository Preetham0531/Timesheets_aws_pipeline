from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional
from models.employee_repository import get_employee_name
from policy_integration import POLICY_ENGINE_AVAILABLE, can_access_record

def json_clean(obj):
    if isinstance(obj, dict):
        return {k: json_clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_clean(v) for v in obj]
    if isinstance(obj, set):
        return [json_clean(v) for v in obj]
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def format_role_metadata(role: dict, user_id: Optional[str] = None, include_policies: bool = True) -> dict:
    formatted = json_clean(role.copy())
    formatted["createdAt"] = role.get("createdAt", "")
    formatted["updatedAt"] = role.get("updatedAt", "")
    formatted["createdByName"] = get_employee_name(role.get("createdById", role.get("createdBy", "")))
    formatted["updatedByName"] = get_employee_name(role.get("updatedById", role.get("updatedBy", "")))
    if include_policies and "Policies" in formatted:
        formatted["policies"] = formatted["Policies"]
        del formatted["Policies"]
    elif "Policies" in formatted:
        del formatted["Policies"]

    if user_id and POLICY_ENGINE_AVAILABLE:
        rid = role.get("rid")
        if rid:
            formatted["_permissions"] = {
                "canEdit":   can_access_record(user_id, "IAM", "modify", rid),
                "canDelete": can_access_record(user_id, "IAM", "delete", rid),
                "canView":   True,
                "isOwner": role.get("createdById", role.get("createdBy")) == user_id
            }
    return formatted

