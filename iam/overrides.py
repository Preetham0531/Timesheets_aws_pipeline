from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
from models.database import GRANTS_TBL
from models.assignment_repository import load_user_assignments
from config import TABLE_CONFIG
from logging_config import create_logger

logger = create_logger("roles.overrides")

def determine_context_and_record_type(module_name: str, has_specific_records: bool) -> Tuple[str, str]:
    mapping = {
        "Projects": "PROJECT",
        "Tasks": "TASK", 
        "Clients": "CLIENT",
        "Contacts": "CONTACT",
        "TimeEntries": "TIME_ENTRY",
        "Employees": "EMPLOYEE",
        "Users": "USER",
        "Reports": "REPORT",
        "Lookups": "LOOKUP",
        "IAM": "ROLE",
        "General": "GENERAL",
        "Dashboard": "DASHBOARD",
        "Approvals": "APPROVAL",
        "ProjectAssignments": "ASSIGNMENT"
    }
    record_type = mapping.get(module_name, module_name.upper())
    context_type = "RECORD_SET" if has_specific_records else "MODULE"
    return context_type, record_type

def generate_module_ovid(module_name: str, context_type: str, record_type: str) -> str:
    if context_type == "RECORD_SET":
        return f"B#OVR#MODULE#{module_name}#CTX#{module_name}"
    return f"B#OVR#MODULE#{module_name}#CTX#{context_type}"

def get_user_module_overrides(user_id: str) -> Dict[str, Dict[str, Any]]:
    assignments = load_user_assignments(user_id)
    out: Dict[str, Dict[str, Any]] = {}
    for a in assignments:
        ov_id = a.get("ovID", "")
        status = (a.get("status") or a.get("Status") or "").lower()
        if status == "active" and ov_id.startswith("B#OVR#MODULE#"):
            mod = a.get("module")
            if mod:
                out[mod] = a
    logger.info(f"Found {len(out)} existing module overrides for user {user_id}")
    return out

def get_user_module_overrides_for_role(user_id: str, base_role_name: str) -> Dict[str, Dict[str, Any]]:
    assignments = load_user_assignments(user_id)
    out: Dict[str, Dict[str, Any]] = {}
    for a in assignments:
        ov_id = a.get("ovID", "")
        status = (a.get("status") or a.get("Status") or "").lower()
        if status == "active" and ov_id.startswith("B#OVR#MODULE#") and a.get("baseRole") == base_role_name:
            mod = a.get("module")
            if mod:
                out[mod] = a
    logger.info(f"Found {len(out)} module overrides for user {user_id} and role {base_role_name}")
    return out

def process_module_override(
    user_id: str,
    caller_id: str,
    module_name: str,
    module_config: Dict[str, Any],
    base_role_name: str,
    base_role_id: str,
    existing_override: Optional[Dict[str, Any]],
    get_user_full_name,  # pass function to resolve names
    now_iso,             # pass function for timestamps
):

    allow_permissions = module_config.get("allow", {})
    deny_permissions = module_config.get("deny", {})
    selected_ids = module_config.get("SelectedIds", {})
    denied_ids = module_config.get("DeniedIds", {})
    selected_creators = module_config.get("SelectedCreators", {})
    denied_creators = module_config.get("DeniedCreators", {})

    has_specific_records = bool(selected_ids or selected_creators or denied_ids or denied_creators)
    context_type, record_type = determine_context_and_record_type(module_name, has_specific_records)
    ov_id = generate_module_ovid(module_name, context_type, record_type)

    action = "update" if existing_override else "create"
    updater_name = get_user_full_name(caller_id)
    now = now_iso()

    record = {
        "userID": user_id,
        "ovID": ov_id,
        "module": module_name,
        "contextType": context_type,
        "recordType": record_type,
        "entityType": "UserOverride",
        "baseRole": base_role_name,
        "baseRoleId": base_role_id,
        "status": "active",
        "Status": "active",
        "note": f"Override: {module_name} module customization for user {user_id}",
        "updatedAt": now,
        "updatedBy": str(caller_id),
        "updatedById": str(caller_id),
        "updatedByName": updater_name,
        "namingConvention": "modular_v2"
    }
    if action == "create":
        record.update({
            "createdAt": now,
            "createdBy": str(caller_id),
            "createdById": str(caller_id),
            "createdByName": updater_name
        })


    if allow_permissions:
        record["Allow"] = allow_permissions
    if deny_permissions:
        record["Deny"] = deny_permissions
    if selected_ids:
        record["SelectedIds"] = selected_ids
    if denied_ids:
        record["DeniedIds"] = denied_ids
    if selected_creators:
        record["SelectedCreators"] = selected_creators
    if denied_creators:
        record["DeniedCreators"] = denied_creators

    GRANTS_TBL.put_item(Item=record)

    return {
        "success": True,
        "action": action,
        "module": module_name,
        "ovID": ov_id,
        "contextType": context_type,
        "recordType": record_type,
        "hasSpecificRecords": has_specific_records,
        "permissions": {
            "allow": allow_permissions,
            "deny": deny_permissions,
            "selectedIds": selected_ids,
            "deniedIds": denied_ids,
            "selectedCreators": selected_creators,
            "deniedCreators": denied_creators
        },
        "timestamp": now
    }
