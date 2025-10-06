"""
Role retrieval service.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime
from logging_config import create_logger
from models import (
    scan_all_roles,
    load_role_by_rid,
    load_role_by_name,
    batch_get_roles_by_ids,
    list_users_by_role,
    load_user_assignments,
    get_employee_name
)
from policy_integration import (
    POLICY_ENGINE_AVAILABLE,
    can_access_record,
    get_allowed_record_ids
)
from formatting import format_role_metadata
from overrides import get_user_module_overrides_for_role
from utils import build_response, encode_token
from config import DEFAULT_PAGE_SIZE

logger = create_logger("services.role_retrieval")


def handle_roles_list_view(user_id: str, event_payload: Dict[str, Any], view_type: str, 
                           include_permissions: bool = False, status_filter: Optional[str] = None) -> Dict[str, Any]:
    """Handle list view of roles."""
    try:
        allowed_result = get_allowed_record_ids(user_id, "IAM", "view")
        pattern = allowed_result.get("pattern", "none")
        
        allowed_all = allowed_result.get("all", False)
        allowed_ids = allowed_result.get("ids", set())
        denied_ids = allowed_result.get("denied_ids", set())
        
        if not isinstance(allowed_ids, set):
            allowed_ids = set(allowed_ids or [])
        if not isinstance(denied_ids, set):
            denied_ids = set(denied_ids or [])
        
        if allowed_all:
            all_roles = scan_all_roles()
            if denied_ids:
                items = [r for r in all_roles if r.get("rid") not in denied_ids]
            else:
                items = all_roles
        else:
            items = batch_get_roles_by_ids(list(allowed_ids)) if allowed_ids else []
        
        if status_filter:
            items = [i for i in items if str(i.get("Status", i.get("status", ""))).lower() == status_filter.lower()]
        
        if view_type == "full":
            formatted = [format_role_metadata(r, user_id if include_permissions else None, include_policies=False) for r in items]
        else:
            formatted = []
            for it in items:
                if it.get("rid") and it.get("role"):
                    formatted.append({
                        "rid": it.get("rid"),
                        "role": it.get("role"),
                        "displayId": it.get("displayId"),
                        "displayName": it.get("displayName"),
                        "status": it.get("Status", it.get("status", "")),
                        "isSystem": it.get("isSystem", False),
                        "createdAt": it.get("createdAt", ""),
                        "updatedAt": it.get("updatedAt", ""),
                        "createdByName": get_employee_name(it.get("createdById", it.get("createdBy", ""))),
                        "updatedByName": get_employee_name(it.get("updatedById", it.get("updatedBy", ""))),
                    })
        
        data = {
            "ok": True,
            "roles": formatted,
            "totalCount": len(formatted),
            "scope": "+".join(allowed_result.get("scopes", [])) or pattern,
            "activeScopes": allowed_result.get("scopes", []),
            "policyEngineAvailable": POLICY_ENGINE_AVAILABLE,
            "filterType": pattern,
            "pattern": pattern,
            "statusFilter": status_filter,
            "includePolicies": False
        }
        if "stats" in allowed_result:
            data["policyStats"] = allowed_result["stats"]
        
        return build_response(event=event_payload, data=data, status=200)
    except Exception as e:
        logger.exception("Roles list view failed")
        return build_response(event=event_payload, error="Internal server error", status=500)


def handle_specific_role_view_by_rid(user_id: str, rid: str, event_payload: Dict[str, Any], 
                                     include_permissions: bool = False, status_filter: Optional[str] = None) -> Dict[str, Any]:
    """Handle specific role view by RID."""
    try:
        if not can_access_record(user_id, "IAM", "view", rid):
            return build_response(event=event_payload, error=f"Not authorized to view role {rid}", status=403)
        
        role = load_role_by_rid(rid)
        if not role:
            return build_response(event=event_payload, error=f"Role not found: {rid}", status=404)
        
        if status_filter:
            st = str(role.get("Status", role.get("status", ""))).lower()
            if st != status_filter:
                return build_response(event=event_payload, error=f"Role {rid} does not match status filter: {status_filter}", status=404)
        
        formatted = format_role_metadata(role, user_id if include_permissions else None, include_policies=True)
        
        resolved_ids = {}
        policies = formatted.get("policies", {})
        for module, mod_policy in policies.items():
            resolved_ids[module] = {}
            allow = mod_policy.get("allow", {})
            for action in allow:
                try:
                    scope_result = get_allowed_record_ids(user_id, module, action)
                    resolved_ids[module][action] = {
                        "all": scope_result.get("all", False),
                        "ids": list(scope_result.get("ids", set())),
                        "denied_ids": list(scope_result.get("denied_ids", set())),
                        "scopes": scope_result.get("scopes", []),
                        "pattern": scope_result.get("pattern", "none")
                    }
                except Exception as e:
                    resolved_ids[module][action] = {"error": str(e)}
        
        data = {
            "ok": True,
            "role": formatted,
            "accessGranted": True,
            "retrievedAt": datetime.utcnow().isoformat() + "Z",
            "retrievedBy": user_id,
            "includePolicies": True,
            "resolvedRecordIds": resolved_ids
        }
        return build_response(event=event_payload, data=data, status=200)
    except Exception as e:
        logger.exception("Specific role view failed")
        return build_response(event=event_payload, error="Internal server error", status=500)


def handle_specific_role_view_by_name(user_id: str, role_name: str, event_payload: Dict[str, Any], 
                                      include_permissions: bool = False, status_filter: Optional[str] = None) -> Dict[str, Any]:
    """Handle specific role view by name."""
    try:
        role = load_role_by_name(role_name)
        if not role:
            return build_response(event=event_payload, error=f"Role not found: {role_name}", status=404)
        rid = role.get("rid")
        return handle_specific_role_view_by_rid(user_id, rid, event_payload, include_permissions, status_filter)
    except Exception as e:
        logger.exception("Role view by name failed")
        return build_response(event=event_payload, error="Internal server error", status=500)


def handle_list_users_by_role(event_payload: Dict[str, Any], rid: Optional[str] = None, 
                              role_name: Optional[str] = None, limit: int = DEFAULT_PAGE_SIZE, 
                              next_token: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Handle listing users assigned to a role."""
    try:
        target_identifier = rid or role_name
        if not target_identifier:
            return build_response(event=event_payload, error="rid or role is required when get=users", status=400)
        
        if rid:
            role_record = load_role_by_rid(rid)
            if not role_record:
                return build_response(event=event_payload, error=f"Role not found for rid: {rid}", status=404)
            target_role_name = role_record.get("role")
        else:
            target_role_name = role_name
        
        users, lek = list_users_by_role(target_role_name, limit=limit, next_token=next_token)
        
        formatted_users = []
        for grant in users:
            uid = str(grant.get("userID") or "")
            if uid:
                formatted_users.append({
                    "userID": uid,
                    "fullName": get_employee_name(uid)
                })
        
        return build_response(event=event_payload, data={
            "ok": True,
            "rid": rid,
            "role": target_role_name,
            "users": formatted_users,
            "nextToken": encode_token(lek),
        }, status=200)
    except Exception as e:
        logger.exception("List users by role failed")
        return build_response(event=event_payload, error="Internal server error", status=500)
