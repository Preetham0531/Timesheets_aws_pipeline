"""
Role deletion service.
"""
from typing import Any, Dict
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from logging_config import create_logger
from models import ROLES_TBL, get_employee_name
from policy_integration import (
    POLICY_ENGINE_AVAILABLE,
    can_access_record,
    get_allowed_record_ids,
    get_accessible_records_filter
)
from utils import build_response, now_iso

logger = create_logger("services.role_deletion")


def delete_role(event: Dict[str, Any], caller_id: str) -> Dict[str, Any]:
    """Delete or deactivate a role."""
    qs = event.get("queryStringParameters") or {}
    rid = (qs.get("rid") or "").strip()
    cascade = str(qs.get("cascade", "false")).lower() == "true"
    dry_run = str(qs.get("dryRun", "false")).lower() == "true"
    idempotent = str(qs.get("idempotent", "true")).lower() == "true"
    
    if not rid:
        return build_response(event=event, error="rid query param required", status=400)
    
    try:
        resp = ROLES_TBL.query(KeyConditionExpression=Key("rid").eq(rid), Limit=1)
        items = resp.get("Items", []) or []
        if not items:
            if cascade and idempotent:
                return build_response(event=event, data={"ok": True, "rid": rid, "deleted": True, "cascade": True}, status=200)
            return build_response(event=event, error=f"role with rid '{rid}' not found", status=404)
        role_item = items[0]
        role_name = role_item.get("role")
    except Exception as e:
        logger.exception("Role lookup failed")
        return build_response(event=event, error="Internal server error", status=500)
    
    try:
        if not can_access_record(caller_id, "IAM", "delete", rid):
            if POLICY_ENGINE_AVAILABLE:
                scope_result = get_allowed_record_ids(caller_id, "IAM", "delete")
                access_filter = get_accessible_records_filter(caller_id, "IAM", "delete")
                data = {
                    "error": "Not authorized to delete this role",
                    "rid": rid,
                    "roleName": role_name,
                    "pattern": access_filter.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", [])
                }
                if scope_result.get("all", False):
                    data["hint"] = f"You have delete access to all roles except {len(scope_result.get('denied_ids', []))} denied ones"
                else:
                    data["allowedCount"] = len(scope_result.get("ids", []))
                    data["hint"] = f"You can only delete {len(scope_result.get('ids', []))} specific roles"
                return build_response(event=event, status=403, data=data)
            return build_response(event=event, status=403, data={"error": "Not authorized to delete this role", "rid": rid})
    except Exception as e:
        logger.exception("Authorization check failed")
        return build_response(event=event, error="Internal server error", status=500)
    
    if role_item.get("isSystem") and cascade:
        return build_response(event=event, error="cannot cascade-delete a system role", status=400)
    if role_name in {"superadmin"} and cascade:
        return build_response(event=event, error=f"'{role_name}' is reserved; hard delete disabled", status=400)
    
    if not cascade:
        if dry_run:
            return build_response(event=event, data={"ok": True, "rid": rid, "roleName": role_name, "status": "inactive", "dryRun": True}, status=200)
        
        updater_name = get_employee_name(caller_id)
        try:
            ROLES_TBL.update_item(
                Key={"rid": role_item["rid"]},
                UpdateExpression="SET #s = :inactive, #u = :now, #ub = :ub, #ubId = :ubId, #ubName = :ubName",
                ExpressionAttributeNames={"#s": "Status", "#u": "updatedAt", "#ub": "updatedBy", "#ubId": "updatedById", "#ubName": "updatedByName"},
                ExpressionAttributeValues={":inactive": "inactive", ":now": now_iso(), ":ub": str(caller_id), ":ubId": str(caller_id), ":ubName": updater_name},
                ConditionExpression=Attr("Status").ne("inactive")
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return build_response(event=event, data={"ok": True, "rid": rid, "roleName": role_name, "status": "inactive"}, status=200)
            msg = str(e)
            if "ValidationException" in msg and ("key element" in msg or "missing" in msg):
                ROLES_TBL.update_item(
                    Key={"rid": role_item["rid"], "role": role_item["role"]},
                    UpdateExpression="SET #s = :inactive, #u = :now, #ub = :ub, #ubId = :ubId, #ubName = :ubName",
                    ExpressionAttributeNames={"#s": "Status", "#u": "updatedAt", "#ub": "updatedBy", "#ubId": "updatedById", "#ubName": "updatedByName"},
                    ExpressionAttributeValues={":inactive": "inactive", ":now": now_iso(), ":ub": str(caller_id), ":ubId": str(caller_id), ":ubName": updater_name},
                )
            else:
                logger.exception("Soft delete failed")
                return build_response(event=event, error="Internal server error", status=500)
        
        return build_response(event=event, data={"ok": True, "rid": rid, "roleName": role_name, "status": "inactive"}, status=200)
    
    # CASCADE DELETE: Hard delete the role from DynamoDB
    if dry_run:
        return build_response(event=event, data={"ok": True, "rid": rid, "roleName": role_name, "deleted": True, "cascade": True, "dryRun": True}, status=200)
    
    try:
        logger.info(f"Hard deleting role {rid} ({role_name}) with cascade=True")
        
        # Try deleting with just primary key (rid)
        try:
            ROLES_TBL.delete_item(
                Key={"rid": role_item["rid"]}
            )
            logger.info(f"✅ Successfully deleted role {rid} using primary key 'rid'")
        except ClientError as e:
            msg = str(e)
            # If it fails due to missing sort key, try with composite key
            if "ValidationException" in msg and ("key element" in msg or "missing" in msg):
                logger.info(f"Retrying deletion with composite key (rid + role)")
                ROLES_TBL.delete_item(
                    Key={"rid": role_item["rid"], "role": role_item["role"]}
                )
                logger.info(f"✅ Successfully deleted role {rid} using composite key")
            else:
                raise
        
        return build_response(event=event, data={"ok": True, "rid": rid, "roleName": role_name, "deleted": True, "cascade": True}, status=200)
        
    except Exception as e:
        logger.exception(f"Hard delete failed for role {rid}")
        return build_response(event=event, error="Failed to delete role", status=500)
