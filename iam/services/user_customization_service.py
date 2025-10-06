"""
User-specific role customization service.
"""
from typing import Any, Dict
from logging_config import create_logger
from models import load_role_by_rid, load_role_by_name, load_user_assignments, get_employee_name, validate_target_user
from policy_integration import can_do
from overrides import get_user_module_overrides, process_module_override
from utils import build_response, now_iso

logger = create_logger("services.user_customization")


def handle_user_role_customization(event: Dict[str, Any], caller_id: str, 
                                   target_user_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user-specific role customization."""
    try:
        if not validate_target_user(target_user_id):
            return build_response(event=event, error=f"Target user {target_user_id} not found or inactive", status=404)
        if not can_do(caller_id, "IAM", "modify") and caller_id != target_user_id:
            return build_response(event=event, error="Not authorized to customize roles for other users", status=403)
        
        base_role_name = (body.get("baseRole") or body.get("role") or "").strip()
        rid = (body.get("rid") or "").strip()
        base_role = load_role_by_rid(rid) if rid else (load_role_by_name(base_role_name) if base_role_name else None)
        if not base_role:
            return build_response(event=event, error=f"Base role not found: {base_role_name or rid}", status=404)
        base_role_name = base_role.get("role")
        
        has_base = any(
            a.get("role")==base_role_name and 
            (a.get("status")=="active" or a.get("Status")=="active") and 
            str(a.get("ovID","")).startswith("A#ROLE#") 
            for a in load_user_assignments(target_user_id)
        )
        if not has_base:
            return build_response(event=event, error=f"User {target_user_id} does not have base role '{base_role_name}'", status=400)
        
        modules_data = body.get("modules", {})
        if not modules_data or not isinstance(modules_data, dict):
            return build_response(event=event, error="modules data is required for user customization", status=400)
        
        existing = get_user_module_overrides(target_user_id)
        created, updated, errors = [], [], []
        for module_name, module_config in modules_data.items():
            try:
                res = process_module_override(
                    target_user_id, caller_id, module_name, module_config,
                    base_role_name, base_role.get("rid"),
                    existing.get(module_name),
                    get_user_full_name=get_employee_name,
                    now_iso=now_iso
                )
                if res["success"]:
                    (created if res["action"] == "create" else updated).append(res)
                else:
                    errors.append(res)
            except Exception as me:
                errors.append({"module": module_name, "error": str(me), "success": False})
        
        return build_response(event=event, data={
            "ok": True,
            "message": "User role customization processed successfully",
            "updateType": "modular_user_customization",
            "targetUserId": target_user_id,
            "baseRole": base_role_name,
            "baseRoleId": base_role.get("rid"),
            "summary": {
                "modulesProcessed": len(modules_data),
                "created": len(created),
                "updated": len(updated),
                "errors": len(errors)
            },
            "results": {"created": created, "updated": updated, "errors": errors},
            "processedAt": now_iso(),
            "processedBy": caller_id,
            "processedByName": get_employee_name(caller_id)
        }, status=200)
    
    except Exception as e:
        logger.exception("User role customization failed")
        return build_response(event=event, error="Internal server error", status=500)
