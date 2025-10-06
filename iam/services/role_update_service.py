"""
Role update service.
"""
import json
from typing import Any, Dict
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from logging_config import create_logger
from models import ROLES_TBL, load_role_by_rid, load_role_by_name, get_employee_name
from policies import normalize_policies_compat, deep_replace_policies
from policy_integration import (
    POLICY_ENGINE_AVAILABLE,
    can_access_record,
    get_allowed_record_ids,
    get_accessible_records_filter
)
from utils import build_response, now_iso

logger = create_logger("services.role_update")


def handle_global_role_update(event: Dict[str, Any], caller_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Handle global role update."""
    rid = (body.get("rid") or body.get("id") or "").strip()
    role_name_fallback = (body.get("role") or "").strip()
    
    existing = None
    if rid:
        try:
            existing = load_role_by_rid(rid)
            if existing:
                rid = existing.get("rid", rid)
        except Exception as e:
            logger.exception("Role lookup by rid failed")
            return build_response(event=event, error="Internal server error", status=500)
    
    if not existing and role_name_fallback:
        try:
            existing = load_role_by_name(role_name_fallback)
            if existing:
                rid = existing.get("rid", rid)
        except Exception as e:
            logger.exception("Role lookup by name failed")
            return build_response(event=event, error="Internal server error", status=500)
    
    if not existing:
        return build_response(event=event, error="role not found for given rid/role", status=404)
    
    try:
        if not can_access_record(caller_id, "IAM", "modify", rid):
            if POLICY_ENGINE_AVAILABLE:
                scope_result = get_allowed_record_ids(caller_id, "IAM", "modify")
                access_filter = get_accessible_records_filter(caller_id, "IAM", "modify")
                data = {
                    "error": "Not authorized to modify this role",
                    "roleId": rid,
                    "roleName": existing.get("role"),
                    "pattern": access_filter.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", []),
                    "updateType": "global"
                }
                if scope_result.get("all", False):
                    data["hint"] = f"You have modify access to all roles except {len(scope_result.get('denied_ids', []))} denied ones"
                else:
                    data["allowedCount"] = len(scope_result.get("ids", []))
                    data["hint"] = f"You can only modify {len(scope_result.get('ids', []))} specific roles"
                return build_response(event=event, status=403, data=data)
            return build_response(event=event, status=403, data={"error": "Not authorized to modify this role", "roleId": rid, "updateType": "global"})
    except Exception as e:
        logger.exception("Authorization check failed")
        return build_response(event=event, error="Internal server error", status=500)
    
    now = now_iso()
    updater_name = get_employee_name(caller_id)
    update_parts = ["#u = :u", "#ub = :ub", "#ubId = :ubId", "#ubName = :ubName"]
    expr_vals = {":u": now, ":ub": str(caller_id), ":ubId": str(caller_id), ":ubName": updater_name}
    expr_names = {"#u": "updatedAt", "#ub": "updatedBy", "#ubId": "updatedById", "#ubName": "updatedByName"}
    
    if "displayName" in body:
        update_parts.append("#d = :d")
        expr_names["#d"] = "displayName"
        expr_vals[":d"] = body["displayName"]
    if "description" in body:
        update_parts.append("#n = :n")
        expr_names["#n"] = "note"
        expr_vals[":n"] = body["description"]
    if "modules" in body and isinstance(body["modules"], dict):
        current_policies = existing.get("Policies", {}) or {}
        patch = normalize_policies_compat(body["modules"])
        merged = deep_replace_policies(current_policies, patch)
        
        update_parts.append("#p = :p")
        expr_names["#p"] = "Policies"
        expr_vals[":p"] = merged
    
    update_expr = "SET " + ", ".join(update_parts)
    
    key_hash_only = {"rid": existing["rid"]}
    key_hash_range = {"rid": existing["rid"], "role": existing.get("role")}
    
    def _do_update(key):
        return ROLES_TBL.update_item(
            Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_vals,
        )
    
    try:
        _do_update(key_hash_only)
    except ClientError as e:
        msg = str(e)
        if "ValidationException" in msg and ("key element" in msg or "missing" in msg):
            if key_hash_range.get("role"):
                _do_update(key_hash_range)
            else:
                return build_response(event=event, error="roles table expects composite key (rid,role) but item has no role", status=500)
        else:
            logger.exception("Role update failed")
            return build_response(event=event, error="Internal server error", status=500)
    
    out = {
        "ok": True,
        "message": "Global role updated successfully",
        "updateType": "global",
        "updatedRid": rid,
        "updatedRole": existing.get("role"),
        "updatedAt": now,
        "updatedById": str(caller_id),
        "updatedByName": updater_name,
    }
    if ":p" in expr_vals: out["policies"] = expr_vals[":p"]
    if ":d" in expr_vals: out["displayName"] = expr_vals[":d"]
    if ":n" in expr_vals: out["description"] = expr_vals[":n"]
    return build_response(event=event, data=out, status=200)
