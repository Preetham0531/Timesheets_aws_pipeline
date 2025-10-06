"""
User-specific role view service with overrides merging.
"""
import json
from typing import Any, Dict
from datetime import datetime
from logging_config import create_logger
from models import load_role_by_rid, load_user_assignments, get_employee_name
from policy_integration import POLICY_ENGINE_AVAILABLE, can_access_record, can_do, get_allowed_record_ids
from overrides import get_user_module_overrides_for_role
from utils import build_response

logger = create_logger("services.user_role_view")


def merge_role_with_overrides(base_role: Dict[str, Any], module_overrides: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Merge base role with user-specific module overrides."""
    try:
        merged_role = json.loads(json.dumps(base_role, default=str))
        base_policies = merged_role.get("Policies", merged_role.get("policies", {})) or {}
        
        for module_name, ov in (module_overrides or {}).items():
            if module_name not in base_policies:
                base_policies[module_name] = {}
            mp = base_policies[module_name]
            
            if ov.get("Allow"):
                mp.setdefault("allow", {})
                for act, perms in ov["Allow"].items():
                    mp["allow"][act] = perms
                    if isinstance(perms, list):
                        from policies import _clean_selective_access_data
                        _clean_selective_access_data(mp, act, perms)
            if ov.get("Deny"):
                mp.setdefault("deny", {})
                for act, perms in ov["Deny"].items():
                    mp["deny"][act] = perms
            if ov.get("SelectedIds"):
                mp.setdefault("SelectedIds", {})
                for act, ids in ov["SelectedIds"].items():
                    mp["SelectedIds"][act] = ids
            if ov.get("DeniedIds"):
                mp.setdefault("DeniedIds", {})
                for act, ids in ov["DeniedIds"].items():
                    mp["DeniedIds"][act] = ids
            if ov.get("SelectedCreators"):
                mp.setdefault("SelectedCreators", {})
                for act, creators in ov["SelectedCreators"].items():
                    mp["SelectedCreators"][act] = creators
            if ov.get("DeniedCreators"):
                mp.setdefault("DeniedCreators", {})
                for act, creators in ov["DeniedCreators"].items():
                    mp["DeniedCreators"][act] = creators
        
        merged_role["policies"] = base_policies
        merged_role["Policies"] = base_policies
        merged_role["_overrideMetadata"] = {
            "hasOverrides": bool(module_overrides),
            "overriddenModules": list((module_overrides or {}).keys()),
            "overrideCount": len(module_overrides or {}),
            "mergedAt": datetime.utcnow().isoformat() + "Z"
        }
        return merged_role
    except Exception:
        logger.exception("Error merging role with overrides")
        return base_role


def build_optimized_user_role_response(
    merged_role: Dict[str, Any],
    module_overrides: Dict[str, Dict[str, Any]],
    target_user_id: str,
    caller_id: str,
    base_role_assignment: Dict[str, Any],
    include_debug: bool = False
) -> Dict[str, Any]:
    """Build optimized response for user-specific role."""
    policies = merged_role.get("policies") or merged_role.get("Policies") or {}
    core_role = {
        "rid": merged_role.get("rid"),
        "role": merged_role.get("role"),
        "displayName": merged_role.get("displayName"),
        "status": merged_role.get("Status", merged_role.get("status")),
        "isSystem": merged_role.get("isSystem", False),
        "policies": policies
    }
    override_summary = {
        "hasOverrides": bool(module_overrides),
        "overriddenModules": list((module_overrides or {}).keys()),
        "count": len(module_overrides or {})
    }
    user_context = {
        "userId": target_user_id,
        "userName": get_employee_name(target_user_id),
        "assignedAt": base_role_assignment.get("createdAt"),
        "assignedBy": get_employee_name(base_role_assignment.get("createdBy", "")),
    }
    response = {
        "ok": True,
        "role": core_role,
        "overrides": override_summary,
        "user": user_context,
        "retrievedAt": datetime.utcnow().isoformat() + "Z"
    }
    if include_debug:
        response["debug"] = {
            "mergedRoleKeys": list(merged_role.keys()),
            "policiesSource": "policies" if merged_role.get("policies") else "Policies" if merged_role.get("Policies") else "none",
            "policiesCount": len(policies),
            "policyModules": list(policies.keys()),
            "overrideMetadata": merged_role.get("_overrideMetadata")
        }
    return response


def get_user_effective_permissions(user_id: str) -> Dict[str, Any]:
    """Get user's effective permissions across all modules."""
    try:
        modules = ["Users","Contacts","Clients","Reports","TimeEntries","Lookups","Projects","IAM","General","Dashboard","Approvals","ProjectAssignments","Tasks","Employees"]
        out: Dict[str, Any] = {}
        for m in modules:
            out[m] = {}
            for action in ["view","create","modify","delete"]:
                try:
                    scope = get_allowed_record_ids(user_id, m, action)
                    out[m][action] = {
                        "hasAccess": scope.get("all", False) or bool(scope.get("ids")),
                        "scope": scope.get("scopes", []),
                        "pattern": scope.get("pattern", "none"),
                        "allowedCount": len(scope.get("ids", [])) if not scope.get("all", False) else "unlimited",
                        "deniedCount": len(scope.get("denied_ids", []))
                    }
                except Exception as e:
                    out[m][action] = {"hasAccess": False, "scope": [], "pattern": "error", "error": str(e)}
        return out
    except Exception:
        logger.exception("Error getting effective permissions")
        return {}


def handle_user_specific_role_view(caller_id: str, rid: str, target_user_id: str, event_payload: Dict[str, Any],
                                   include_permissions: bool = False, status_filter: str = None) -> Dict[str, Any]:
    """Handle user-specific role view with overrides."""
    try:
        query = event_payload.get("queryStringParameters") or {}
        include_debug = query.get("debug", "").lower() == "true"
        
        if not can_access_record(caller_id, "IAM", "view", rid):
            return build_response(event=event_payload, error=f"Not authorized to view role {rid}", status=403)
        if caller_id != target_user_id and not can_do(caller_id, "Users", "view"):
            return build_response(event=event_payload, error="Not authorized to view user role customizations", status=403)
        
        base_role = load_role_by_rid(rid)
        if not base_role:
            return build_response(event=event_payload, error=f"Role not found: {rid}", status=404)
        
        base_role_name = base_role.get("role")
        user_assignments = load_user_assignments(target_user_id)
        base_role_assignment = None
        for a in user_assignments:
            if a.get("role") == base_role_name and (a.get("status") == "active" or a.get("Status") == "active") and str(a.get("ovID","")).startswith("A#ROLE#"):
                base_role_assignment = a
                break
        if not base_role_assignment:
            return build_response(event=event_payload, error=f"User does not have the base role '{base_role_name}'", status=404)
        
        module_overrides = get_user_module_overrides_for_role(target_user_id, base_role_name)
        merged = merge_role_with_overrides(base_role, module_overrides)
        resp = build_optimized_user_role_response(merged, module_overrides, target_user_id, caller_id, base_role_assignment, include_debug)
        
        if include_permissions and POLICY_ENGINE_AVAILABLE:
            resp["effectivePermissions"] = get_user_effective_permissions(target_user_id)
        
        return build_response(event=event_payload, data=resp, status=200)
    except Exception as e:
        logger.exception("User-specific role view failed")
        return build_response(event=event_payload, error="Internal server error", status=500)
