"""
Role creation service.
"""
import json
import uuid
from typing import Any, Dict
from logging_config import create_logger
from models import (
    ROLES_TBL,
    role_exists,
    update_sequence_and_get_display,
    get_employee_name
)
from policies import normalize_policies_compat, has_any_allow
from policy_integration import POLICY_ENGINE_AVAILABLE, can_do, get_allowed_record_ids
from utils import build_response, now_iso

logger = create_logger("services.role_creation")


def create_role(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Create a new role with policies."""
    try:
        if not can_do(caller_id, "IAM", "create"):
            if POLICY_ENGINE_AVAILABLE:
                scope_result = get_allowed_record_ids(caller_id, "IAM", "create")
                return build_response(event=event, status=403, data={
                    "error": "Not authorized to create roles",
                    "pattern": scope_result.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", []),
                    "hasAllAccess": scope_result.get("all", False)
                })
            return build_response(event=event, status=403, data={"error": "Not authorized to create roles"})
    except Exception as e:
        return build_response(event=event, status=500, data={"error": "Authorization system error", "details": str(e)})
    
    try:
        body = json.loads(event.get("body", "{}")) or {}
    except json.JSONDecodeError:
        return build_response(event=event, error="Invalid JSON in request body", status=400)
    
    role_name = (body.get("role") or "").strip()
    display = (body.get("displayName") or role_name).strip()
    description = (body.get("description") or "").strip()
    modules = body.get("modules") or {}
    
    if not role_name:
        return build_response(event=event, error="role is required", status=400)
    if not isinstance(modules, dict):
        return build_response(event=event, error="modules must be an object", status=400)
    if role_exists(role_name):
        return build_response(event=event, error=f"role '{role_name}' already exists", status=409)
    
    policies = normalize_policies_compat(modules)
    if not has_any_allow(policies):
        return build_response(event=event, error="no permissions provided", status=400)
    
    rid = str(uuid.uuid4())
    now = now_iso()
    display_id = update_sequence_and_get_display("ROL")
    creator_name = get_employee_name(caller_id)
    
    item = {
        "rid": rid,
        "role": role_name,
        "displayId": display_id,
        "displayName": display or role_name,
        "note": description,
        "isSystem": False,
        "Policies": policies,
        "Status": "active",
        "createdAt": now,
        "createdById": str(caller_id),
        "createdByName": creator_name,
    }
    
    try:
        ROLES_TBL.put_item(Item=item)
        return build_response(
            event=event,
            data={
                "message": "Role created successfully",
                "role": {
                    "rid": rid,
                    "role": role_name,
                    "displayId": display_id,
                    "displayName": item["displayName"],
                    "status": item["Status"],
                    "policies": policies,
                    "createdAt": now,
                    "createdById": item["createdById"],
                    "createdByName": item["createdByName"],
                }
            },
            status=201,
        )
    except Exception as e:
        logger.exception("Role creation failed")
        return build_response(event=event, error="Internal server error", status=500)
