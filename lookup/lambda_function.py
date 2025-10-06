import os
import json
import boto3
import logging
import traceback
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

from utils import build_response, get_cors_headers
from policy_engine import can_do, can_access_record, get_user_permissions_debug

# ===================================================
# Setup Logging
# ===================================================
logger = logging.getLogger("lookup_handler")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ===================================================
# Environment Variables & DynamoDB Setup
# ===================================================
LOOKUP_TABLE_NAME = os.environ.get("LOOKUP_TABLE")

try:
    dynamodb = boto3.resource("dynamodb")
    lookup_table = dynamodb.Table(LOOKUP_TABLE_NAME)
    logger.info(f"✅ Connected to DynamoDB table: {LOOKUP_TABLE_NAME}")
except Exception as e:
    logger.error(f"❌ Failed to connect to DynamoDB: {e}")
    raise

# ===================================================
# Constants
# ===================================================
MODULE_NUMBER_WIDTH = 3
LIST_NUMBER_WIDTH = 2
SEQUENCE_NUMBER_WIDTH = 3

# Supported modules with their numeric IDs
MODULE_IDENTIFIER_MAP = {
    "employee": "100",
    "users": "200", 
    "customers": "300",
    "contacts": "400",
}

# Lookup list identifiers grouped by module
LOOKUP_LIST_IDENTIFIER_MAP = {
    "employee": {
        "designation": "01",
        "department": "02",
        "category": "03",
        "employmentType": "04",
        "branch": "05",
    },
    "customers": {
        "category": "01",
        "department": "02",
        "type": "03",
        "priority": "04",
        "status": "05"
    },
    "contacts": {
        "designation": "01",
        "department": "02",
        "type": "03"
    },
    "users": {
        "role": "01",
        "department": "02",
        "level": "03"
    },
}

# ===================================================
# Core Helper Functions
# ===================================================

def extract_user_id(authorizer_context: Dict[str, Any]) -> Optional[str]:
    """
    Extract user ID from authorizer context with multiple fallback keys
    """
    user_id = (
        authorizer_context.get("user_id") or
        authorizer_context.get("userID") or  
        authorizer_context.get("principalId") or
        authorizer_context.get("sub") or
        authorizer_context.get("userId")
    )
    
    logger.info(f"👤 Extracted user_id: {user_id}")
    logger.info(f"🔍 Available authorizer keys: {list(authorizer_context.keys())}")
    
    return user_id

def check_module_authorization(user_id: str, module: str, action: str) -> Tuple[bool, str]:
    """
    Check module-level authorization using policy engine only
    """
    if not user_id:
        return False, "Missing user authentication"
    
    try:
        has_access = can_do(user_id, module, action)
        if has_access:
            logger.info(f"✅ Policy engine granted {action} access to {module} for {user_id}")
            return True, "authorized"
        else:
            logger.warning(f"❌ Policy engine denied {action} access to {module} for {user_id}")
            return False, f"Not authorized to {action} {module.lower()} records"
    except Exception as e:
        logger.error(f"❌ Policy engine error for module check: {e}")
        return False, f"Authorization system error: {str(e)}"

def check_record_authorization(user_id: str, module: str, action: str, record_id: str) -> Tuple[bool, str]:
    """
    Check record-specific authorization using policy engine only
    """
    try:
        has_access = can_access_record(user_id, module, action, record_id)
        if has_access:
            logger.info(f"✅ Record access granted: {user_id} can {action} {record_id}")
            return True, "authorized"
        else:
            logger.warning(f"❌ Record access denied: {user_id} cannot {action} {record_id}")
            return False, f"Not authorized to {action} this specific record"
    except Exception as e:
        logger.error(f"❌ Record authorization error: {e}")
        return False, f"Authorization system error: {str(e)}"

def build_code_prefix(module_number: int, list_number: int) -> str:
    """Generate a prefix for codes using module_number + list_number with zero-padding."""
    return f"{module_number:0{MODULE_NUMBER_WIDTH}}{list_number:0{LIST_NUMBER_WIDTH}}"

def resolve_lookup_identifiers(module_name: str, list_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve module_name and list_name into their numeric IDs."""
    logger.info(f"🔍 Resolving identifiers - module: '{module_name}', list: '{list_name}'")
    
    module_id = MODULE_IDENTIFIER_MAP.get(module_name)
    list_id = LOOKUP_LIST_IDENTIFIER_MAP.get(module_name, {}).get(list_name)
    
    logger.info(f"✅ Resolved - module_id: '{module_id}', list_id: '{list_id}'")
    
    if not module_id:
        logger.warning(f"❌ Unknown module: {module_name}. Available: {list(MODULE_IDENTIFIER_MAP.keys())}")
    
    if not list_id:
        available_lists = list(LOOKUP_LIST_IDENTIFIER_MAP.get(module_name, {}).keys())
        logger.warning(f"❌ Unknown list: {list_name} for module {module_name}. Available: {available_lists}")
    
    return module_id, list_id

def get_current_timestamp() -> str:
    """Get current UTC timestamp in ISO format"""
    return datetime.utcnow().isoformat() + "Z"

def _success_response(data, event, cors_headers, status=200):
    """Helper for building successful API responses with CORS headers."""
    response = build_response(data=data, event=event, status=status)
    response["headers"] = cors_headers
    return response

def _error_response(message, status, event, cors_headers, extra_data=None):
    """Helper for building error API responses with CORS headers."""
    error_data = {"error": message}
    if extra_data:
        error_data.update(extra_data)
    
    response = build_response(data=error_data, status=status, event=event)
    response["headers"] = cors_headers
    return response

def _enrich_with_permissions(record: Dict[str, Any], user_id: str, module_id: str, lookup_list_id: str) -> Dict[str, Any]:
    """
    Attach comprehensive permissions metadata using policy engine only
    """
    record_id = f"{module_id}:{lookup_list_id}"
    
    # Check each permission individually using policy engine
    can_view, _ = check_record_authorization(user_id, "Lookups", "view", record_id)
    can_modify, _ = check_record_authorization(user_id, "Lookups", "modify", record_id)
    can_delete, _ = check_record_authorization(user_id, "Lookups", "delete", record_id)
    can_create, _ = check_record_authorization(user_id, "Lookups", "create", record_id)
    
    record["_permissions"] = {
        "canView": can_view,
        "canModify": can_modify,
        "canDelete": can_delete,
        "canCreate": can_create,
        "canManage": can_modify and can_delete,
        "recordId": record_id,
        "evaluatedAt": get_current_timestamp(),
        "authorizationMethod": "policy_engine_only",
        "evaluatedFor": user_id
    }
    
    return record

def get_available_modules_and_lists() -> Dict[str, Any]:
    """Get available modules and their lookup lists for error responses"""
    return {
        "modules": list(MODULE_IDENTIFIER_MAP.keys()),
        "lookup_lists": {
            module: list(lists.keys()) 
            for module, lists in LOOKUP_LIST_IDENTIFIER_MAP.items()
        }
    }

# ===================================================
# Main Lambda Handler
# ===================================================
def lambda_handler(event: Dict[str, Any], context: Any):
    """
    Complete lookup handler with pure policy engine authorization
    Current User: tatireddyp1-sys
    Date: 2025-09-17 10:44:27 UTC
    """
    cors_headers = get_cors_headers(event)
    
    try:
        
        http_method = (event.get("httpMethod") or "").upper()
        if http_method == "OPTIONS":
            return _success_response({"message": "CORS preflight successful"}, event, cors_headers)
        logger.info(f"🚀 Lookup request: {http_method} at {get_current_timestamp()}")

        # Extract user ID from authorizer context
        authorizer_context = event.get("requestContext", {}).get("authorizer", {})
        user_id = extract_user_id(authorizer_context)
        
        if not user_id:
            logger.error("❌ No user authentication found")
            return _error_response(
                "Missing user authentication", 
                401, 
                event, 
                cors_headers,
                {
                    "availableKeys": list(authorizer_context.keys()),
                    "timestamp": get_current_timestamp()
                }
            )

        logger.info(f"👤 Processing request for user: {user_id}")

       
        query_params = event.get("queryStringParameters") or {}
        if query_params.get("debug") == "true":
            try:
                debug_info = get_user_permissions_debug(user_id, "Lookups")
                return _success_response({
                    "user_id": user_id,
                    "current_user": "tatireddyp1-sys",
                    "permissions_debug": debug_info,
                    "authorization_method": "policy_engine_only",
                    "available_data": get_available_modules_and_lists(),
                    "timestamp": get_current_timestamp()
                }, event, cors_headers)
            except Exception as e:
                logger.error(f"Debug endpoint error: {e}")
                return _error_response(f"Debug failed: {str(e)}", 500, event, cors_headers)

        # ===================================================
        # GET /lookup
        # ===================================================
        if http_method == "GET":
            # Check module-level authorization
            is_authorized, auth_reason = check_module_authorization(user_id, "Lookups", "view")
            if not is_authorized:
                return _error_response(auth_reason, 403, event, cors_headers)

            module_name = (query_params.get("module") or "").lower().strip()
            lookup_list_name = (query_params.get("lookUpList") or "").strip()
            
            logger.info(f"📋 GET Request - Module: '{module_name}', List: '{lookup_list_name}'")
            
            if not module_name or not lookup_list_name:
                return _error_response(
                    "module and lookUpList are required", 
                    400, 
                    event, 
                    cors_headers,
                    {
                        "example_usage": "?module=customers&lookUpList=category",
                        **get_available_modules_and_lists()
                    }
                )

            module_id, lookup_list_id = resolve_lookup_identifiers(module_name, lookup_list_name)
            if not module_id or not lookup_list_id:
                return _error_response(
                    f"Unknown module '{module_name}' or lookUpList '{lookup_list_name}'", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            # Check record-specific authorization
            record_id = f"{module_id}:{lookup_list_id}"
            can_access, access_reason = check_record_authorization(user_id, "Lookups", "view", record_id)
            if not can_access:
                return _error_response(access_reason, 403, event, cors_headers)

            # Get the record from DynamoDB
            try:
                response = lookup_table.get_item(
                    Key={"module_id": module_id, "lookUpList_id": lookup_list_id}
                )
                record = response.get("Item")
                
                if not record:
                    return _error_response(
                        f"Lookup list not found: {module_name}/{lookup_list_name}", 
                        404, 
                        event, 
                        cors_headers
                    )

                # Enrich with permissions
                record = _enrich_with_permissions(record, user_id, module_id, lookup_list_id)
                
                logger.info(f"✅ Successfully retrieved lookup: {module_name}/{lookup_list_name}")
                return _success_response(record, event, cors_headers)
                
            except Exception as e:
                logger.error(f"❌ Database error during GET: {e}")
                return _error_response(f"Database error: {str(e)}", 500, event, cors_headers)

        # ===================================================
        # POST /lookup
        # ===================================================
        elif http_method == "POST":
            # Check module-level authorization
            is_authorized, auth_reason = check_module_authorization(user_id, "Lookups", "create")
            if not is_authorized:
                return _error_response(auth_reason, 403, event, cors_headers)

            try:
                body = json.loads(event.get("body") or "{}")
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON decode error: {e}")
                return _error_response("Invalid JSON in request body", 400, event, cors_headers)

            module_name = (body.get("module") or "").lower().strip()
            lookup_list_name = (body.get("lookUpList") or "").strip()
            action_type = (body.get("action") or "").lower().strip()
            new_fields = body.get("fields") or []

            logger.info(f"📝 POST Request - Module: '{module_name}', List: '{lookup_list_name}', Action: '{action_type}'")

            if not module_name or not lookup_list_name or action_type not in {"create", "add"}:
                return _error_response(
                    "module, lookUpList, and valid action (create/add) are required", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            if not isinstance(new_fields, list) or not new_fields:
                return _error_response(
                    "fields must be a non-empty array", 
                    400, 
                    event, 
                    cors_headers
                )

            module_id, lookup_list_id = resolve_lookup_identifiers(module_name, lookup_list_name)
            if not module_id or not lookup_list_id:
                return _error_response(
                    f"Unknown module '{module_name}' or lookUpList '{lookup_list_name}'", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            # Check record-specific authorization
            record_id = f"{module_id}:{lookup_list_id}"
            can_access, access_reason = check_record_authorization(user_id, "Lookups", "create", record_id)
            if not can_access:
                return _error_response(access_reason, 403, event, cors_headers)

            try:
                current_time = get_current_timestamp()
                
                if action_type == "create":
                    # Create new lookup list
                    try:
                        lookup_table.put_item(
                            Item={
                                "module_id": module_id, 
                                "lookUpList_id": lookup_list_id, 
                                "fields": new_fields,
                                "createdAt": current_time,
                                "createdBy": user_id,
                                "updatedAt": current_time,
                                "updatedBy": user_id
                            },
                            ConditionExpression="attribute_not_exists(module_id)"
                        )
                        
                        new_record = {
                            "module_id": module_id, 
                            "lookUpList_id": lookup_list_id, 
                            "fields": new_fields,
                            "createdAt": current_time,
                            "createdBy": user_id
                        }
                        new_record = _enrich_with_permissions(new_record, user_id, module_id, lookup_list_id)
                        
                        logger.info(f"✅ Created lookup list: {module_name}/{lookup_list_name}")
                        return _success_response(new_record, event, cors_headers, 201)
                        
                    except lookup_table.meta.client.exceptions.ConditionalCheckFailedException:
                        return _error_response(
                            f"Lookup list already exists: {module_name}/{lookup_list_name}", 
                            409, 
                            event, 
                            cors_headers
                        )
                
                else:  # action_type == "add"
                    # Add fields to existing list
                    response = lookup_table.get_item(
                        Key={"module_id": module_id, "lookUpList_id": lookup_list_id}
                    )
                    record = response.get("Item")
                    
                    prefix = build_code_prefix(int(module_id), int(lookup_list_id))
                    
                    if record and record.get("fields"):
                        existing_codes = [
                            int(f["code"]) for f in record["fields"] 
                            if f.get("code", "").startswith(prefix)
                        ]
                        if existing_codes:
                            max_existing_code = max(existing_codes)
                            next_sequence_number = (max_existing_code - int(prefix) * (10**SEQUENCE_NUMBER_WIDTH)) + 1
                        else:
                            next_sequence_number = 1
                    else:
                        next_sequence_number = 1
                        # Create empty list if doesn't exist
                        try:
                            lookup_table.put_item(
                                Item={
                                    "module_id": module_id, 
                                    "lookUpList_id": lookup_list_id, 
                                    "fields": [],
                                    "createdAt": current_time,
                                    "createdBy": user_id,
                                    "updatedAt": current_time,
                                    "updatedBy": user_id
                                },
                                ConditionExpression="attribute_not_exists(module_id)"
                            )
                        except lookup_table.meta.client.exceptions.ConditionalCheckFailedException:
                            pass  # Already exists

                    # Add codes to new fields
                    for entry in new_fields:
                        entry["code"] = f"{prefix}{next_sequence_number:0{SEQUENCE_NUMBER_WIDTH}}"
                        entry["valueType"] = "user"
                        entry["createdAt"] = current_time
                        entry["createdBy"] = user_id
                        next_sequence_number += 1

                    # Update with new fields
                    lookup_table.update_item(
                        Key={"module_id": module_id, "lookUpList_id": lookup_list_id},
                        UpdateExpression="SET #f = list_append(if_not_exists(#f, :empty), :vals), #ua = :updated_at, #ub = :updated_by",
                        ExpressionAttributeNames={
                            "#f": "fields",
                            "#ua": "updatedAt", 
                            "#ub": "updatedBy"
                        },
                        ExpressionAttributeValues={
                            ":vals": new_fields, 
                            ":empty": [],
                            ":updated_at": current_time,
                            ":updated_by": user_id
                        },
                    )

                    # Get updated record
                    updated_response = lookup_table.get_item(
                        Key={"module_id": module_id, "lookUpList_id": lookup_list_id}
                    )
                    updated_record = updated_response.get("Item")
                    
                    updated_record = _enrich_with_permissions(updated_record, user_id, module_id, lookup_list_id)
                    
                    logger.info(f"✅ Added {len(new_fields)} fields to lookup list: {module_name}/{lookup_list_name}")
                    return _success_response(updated_record, event, cors_headers)
                    
            except Exception as e:
                logger.error(f"❌ Database error during POST: {e}")
                logger.error(f"❌ Traceback: {traceback.format_exc()}")
                return _error_response(f"Database error: {str(e)}", 500, event, cors_headers)

        # ===================================================
        # PUT /lookup
        # ===================================================
        elif http_method == "PUT":
            # Check module-level authorization
            is_authorized, auth_reason = check_module_authorization(user_id, "Lookups", "modify")
            if not is_authorized:
                return _error_response(auth_reason, 403, event, cors_headers)

            try:
                body = json.loads(event.get("body") or "{}")
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON decode error: {e}")
                return _error_response("Invalid JSON in request body", 400, event, cors_headers)

            module_name = (body.get("module") or "").lower().strip()
            lookup_list_name = (body.get("lookUpList") or "").strip()
            fields_to_update = body.get("fields") or []

            logger.info(f"✏️ PUT Request - Module: '{module_name}', List: '{lookup_list_name}'")

            if not module_name or not lookup_list_name or not isinstance(fields_to_update, list):
                return _error_response(
                    "module, lookUpList, and fields are required", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            if not fields_to_update:
                return _error_response(
                    "fields array cannot be empty", 
                    400, 
                    event, 
                    cors_headers
                )

            module_id, lookup_list_id = resolve_lookup_identifiers(module_name, lookup_list_name)
            if not module_id or not lookup_list_id:
                return _error_response(
                    f"Unknown module '{module_name}' or lookUpList '{lookup_list_name}'", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            # Check record-specific authorization
            record_id = f"{module_id}:{lookup_list_id}"
            can_access, access_reason = check_record_authorization(user_id, "Lookups", "modify", record_id)
            if not can_access:
                return _error_response(access_reason, 403, event, cors_headers)

            try:
                response = lookup_table.get_item(
                    Key={"module_id": module_id, "lookUpList_id": lookup_list_id}
                )
                record = response.get("Item")
                
                if not record:
                    return _error_response(
                        f"Lookup list not found: {module_name}/{lookup_list_name}", 
                        404, 
                        event, 
                        cors_headers
                    )

                existing_fields_map = {f["code"]: f for f in record.get("fields", [])}
                record_updated = False
                current_time = get_current_timestamp()

                for field_update in fields_to_update:
                    code = field_update.get("code")
                    if code and code in existing_fields_map:
                        # Add update metadata
                        field_update["updatedAt"] = current_time
                        field_update["updatedBy"] = user_id
                        
                        existing_fields_map[code].update(field_update)
                        record_updated = True

                if not record_updated:
                    return _error_response(
                        "No matching codes found to update", 
                        400, 
                        event, 
                        cors_headers,
                        {
                            "providedCodes": [f.get("code") for f in fields_to_update],
                            "availableCodes": list(existing_fields_map.keys())
                        }
                    )

                updated_fields = list(existing_fields_map.values())
                lookup_table.update_item(
                    Key={"module_id": module_id, "lookUpList_id": lookup_list_id},
                    UpdateExpression="SET #f = :vals, #ua = :updated_at, #ub = :updated_by",
                    ExpressionAttributeNames={
                        "#f": "fields",
                        "#ua": "updatedAt",
                        "#ub": "updatedBy"
                    },
                    ExpressionAttributeValues={
                        ":vals": updated_fields,
                        ":updated_at": current_time,
                        ":updated_by": user_id
                    },
                )

                updated_record = {"fields": updated_fields}
                updated_record = _enrich_with_permissions(updated_record, user_id, module_id, lookup_list_id)
                
                logger.info(f"✅ Updated lookup list: {module_name}/{lookup_list_name}")
                return _success_response(updated_record, event, cors_headers)
                
            except Exception as e:
                logger.error(f"❌ Database error during PUT: {e}")
                logger.error(f"❌ Traceback: {traceback.format_exc()}")
                return _error_response(f"Database error: {str(e)}", 500, event, cors_headers)

        # ===================================================
        # DELETE /lookup
        # ===================================================
        elif http_method == "DELETE":
            # Check module-level authorization
            is_authorized, auth_reason = check_module_authorization(user_id, "Lookups", "delete")
            if not is_authorized:
                return _error_response(auth_reason, 403, event, cors_headers)

            try:
                body = json.loads(event.get("body") or "{}")
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON decode error: {e}")
                return _error_response("Invalid JSON in request body", 400, event, cors_headers)

            module_name = (body.get("module") or "").lower().strip()
            lookup_list_name = (body.get("lookUpList") or "").strip()
            codes_to_delete = body.get("codes") or []

            logger.info(f"🗑️ DELETE Request - Module: '{module_name}', List: '{lookup_list_name}'")

            if not module_name or not lookup_list_name or not isinstance(codes_to_delete, list) or not codes_to_delete:
                return _error_response(
                    "module, lookUpList, and codes are required", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            module_id, lookup_list_id = resolve_lookup_identifiers(module_name, lookup_list_name)
            if not module_id or not lookup_list_id:
                return _error_response(
                    f"Unknown module '{module_name}' or lookUpList '{lookup_list_name}'", 
                    400, 
                    event, 
                    cors_headers,
                    get_available_modules_and_lists()
                )

            # Check record-specific authorization
            record_id = f"{module_id}:{lookup_list_id}"
            can_access, access_reason = check_record_authorization(user_id, "Lookups", "delete", record_id)
            if not can_access:
                return _error_response(access_reason, 403, event, cors_headers)

            try:
                response = lookup_table.get_item(
                    Key={"module_id": module_id, "lookUpList_id": lookup_list_id}
                )
                record = response.get("Item")
                
                if not record:
                    return _error_response(
                        f"Lookup list not found: {module_name}/{lookup_list_name}", 
                        404, 
                        event, 
                        cors_headers
                    )

                original_fields = record.get("fields", [])
                remaining_fields = [f for f in original_fields if f.get("code") not in codes_to_delete]

                if len(remaining_fields) == len(original_fields):
                    return _error_response(
                        "No matching codes found to delete", 
                        400, 
                        event, 
                        cors_headers,
                        {
                            "requestedCodes": codes_to_delete,
                            "availableCodes": [f.get("code") for f in original_fields]
                        }
                    )

                current_time = get_current_timestamp()
                lookup_table.update_item(
                    Key={"module_id": module_id, "lookUpList_id": lookup_list_id},
                    UpdateExpression="SET #f = :vals, #ua = :updated_at, #ub = :updated_by",
                    ExpressionAttributeNames={
                        "#f": "fields",
                        "#ua": "updatedAt",
                        "#ub": "updatedBy"
                    },
                    ExpressionAttributeValues={
                        ":vals": remaining_fields,
                        ":updated_at": current_time,
                        ":updated_by": user_id
                    },
                )

                deleted_record = {
                    "deletedCodes": codes_to_delete,
                    "remainingFieldsCount": len(remaining_fields),
                    "deletedCount": len(codes_to_delete),
                    "deletedAt": current_time,
                    "deletedBy": user_id
                }
                deleted_record = _enrich_with_permissions(deleted_record, user_id, module_id, lookup_list_id)
                
                logger.info(f"✅ Deleted {len(codes_to_delete)} codes from lookup list: {module_name}/{lookup_list_name}")
                return _success_response(deleted_record, event, cors_headers)
                
            except Exception as e:
                logger.error(f"❌ Database error during DELETE: {e}")
                logger.error(f"❌ Traceback: {traceback.format_exc()}")
                return _error_response(f"Database error: {str(e)}", 500, event, cors_headers)

        # ===================================================
        # Unsupported Method
        # ===================================================
        else:
            return _error_response(f"{http_method} not supported", 405, event, cors_headers)

    except json.JSONDecodeError as e:
        logger.error(f"❌ Global JSON decode error: {e}")
        return _error_response("Invalid JSON in request", 400, event, cors_headers)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return _error_response(f"Internal server error: {str(e)}", 500, event, cors_headers)