"""
Role handler for routing and request orchestration.
"""
import json
from typing import Any, Dict
from logging_config import create_logger
from policy_integration import POLICY_ENGINE_AVAILABLE, can_do, get_allowed_record_ids
from services import (
    create_role,
    handle_roles_list_view,
    handle_specific_role_view_by_rid,
    handle_specific_role_view_by_name,
    handle_list_users_by_role,
    handle_user_specific_role_view,
    handle_global_role_update,
    delete_role,
    handle_user_role_customization
)
from utils import build_response, decode_token
from config import DEFAULT_PAGE_SIZE

logger = create_logger("handlers.role_handler")


def handle_options_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle OPTIONS request for CORS preflight."""
    return build_response(
        event=event,
        data={
            "ok": True,
            "supportedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "policyEngineEnabled": POLICY_ENGINE_AVAILABLE,
            "supportsUserCustomization": True,
            "operationTypes": {
                "global": "Operations without user_id query parameter affect global roles",
                "userCustomization": "Operations with user_id query parameter create/modify user-specific overrides"
            },
            "queryParameters": {
                "user_id": "Target user ID for role customization operations",
                "userId": "Alternative parameter name for user_id"
            }
        },
        status=200
    )


def handle_post_request(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Handle POST request for role creation."""
    return create_role(event, caller_id)


def handle_get_request(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Handle GET request for role retrieval."""
    try:
        if not can_do(caller_id, "IAM", "view"):
            if POLICY_ENGINE_AVAILABLE:
                scope_result = get_allowed_record_ids(caller_id, "IAM", "view")
                return build_response(event=event, status=403, data={
                    "error": "Not authorized to view roles",
                    "pattern": scope_result.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", []),
                    "hasAllAccess": scope_result.get("all", False)
                })
            return build_response(event=event, status=403, data={"error": "Not authorized to view roles"})
    except Exception as e:
        return build_response(event=event, status=500, data={"error": "Authorization system error", "details": str(e)})
    
    qs = event.get("queryStringParameters") or {}
    rid = (qs.get("rid") or "").strip()
    role_name = (qs.get("role") or "").strip()
    target_user_id = (qs.get("user_id") or qs.get("userID") or "").strip()
    status_filter = (qs.get("status") or "").strip().lower()
    get_what = (qs.get("get") or "").strip().lower()
    view_type = qs.get("view", "full")
    include_permissions = qs.get("includePermissions", "").lower() == "true"
    
    try:
        limit = int(qs.get("limit", DEFAULT_PAGE_SIZE))
        if limit < 1 or limit > 200:
            limit = DEFAULT_PAGE_SIZE
    except:
        limit = DEFAULT_PAGE_SIZE
    
    next_token = decode_token(qs.get("nextToken"))
    
    if get_what == "users":
        return handle_list_users_by_role(event, rid=rid, role_name=role_name, limit=limit, next_token=next_token)
    elif rid and target_user_id:
        return handle_user_specific_role_view(caller_id, rid, target_user_id, event, include_permissions, status_filter)
    elif rid:
        return handle_specific_role_view_by_rid(caller_id, rid, event, include_permissions, status_filter)
    elif role_name:
        return handle_specific_role_view_by_name(caller_id, role_name, event, include_permissions, status_filter)
    else:
        return handle_roles_list_view(caller_id, event, view_type, include_permissions, status_filter)


def handle_put_request(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Handle PUT request for role updates."""
    try:
        body = json.loads(event.get("body", "{}")) or {}
    except json.JSONDecodeError:
        return build_response(event=event, error="Invalid JSON in request body", status=400)
    
    query = event.get("queryStringParameters") or {}
    target_user_id = query.get("user_id") or query.get("userId")
    
    if target_user_id:
        return handle_user_role_customization(event, caller_id, target_user_id, body)
    return handle_global_role_update(event, caller_id, body)


def handle_delete_request(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Handle DELETE request for role deletion."""
    return delete_role(event, caller_id)


def extract_caller_identity(event: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """Extract caller identity from the event."""
    authz_ctx = (event.get("requestContext", {}) or {}).get("authorizer", {}) or {}
    caller_id = authz_ctx.get("sub") or authz_ctx.get("user_id") or (event.get("headers", {}) or {}).get("x-user-id")
    
    if not caller_id:
        return None, build_response(event=event, error="missing user identity", status=401)
    
    return caller_id, None
