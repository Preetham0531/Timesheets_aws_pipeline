from __future__ import annotations
import os
import json
import fnmatch
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, Set, Union
from datetime import datetime, timezone
import threading
from boto3.dynamodb.conditions import Key, Attr
import boto3
import logging

# ========= ENHANCED LOGGING =========
_LOG_LEVEL = os.getenv("POLICY_ENGINE_LOG_LEVEL", "INFO").upper()
logger = logging.getLogger("policy_engine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(_LOG_LEVEL)

# ========= CONSTANTS =========
MAX_JSON_LOG_LENGTH = 2000
BATCH_SIZE = 100
DEFAULT_STATUS = "active"
CACHE_TTL = 300  # 5 minutes

# ========= ENVIRONMENT CONFIGURATION =========
TABLE_CONFIG = {
    "assignments": "dev.UserGrants.ddb-table",
    "roles": "dev.roles_t.ddb-table", 
    "definitions": "dev.PolicyDefinitions.ddb-table",
    "role_index": "role-rid-index"
}

# ========= AWS RESOURCES =========
_ddb = boto3.resource("dynamodb")
_tables = {
    "assignments": _ddb.Table(TABLE_CONFIG["assignments"]),
    "roles": _ddb.Table(TABLE_CONFIG["roles"]),
    "definitions": _ddb.Table(TABLE_CONFIG["definitions"])
}

# ========= THREAD-SAFE RESOLVER REGISTRY =========
_resolvers_lock = threading.RLock()
_RESOLVERS: Dict[str, Callable] = {}

def register_resolver(resource_type: str, resolver: Callable) -> None:
    """Thread-safe resolver registration"""
    with _resolvers_lock:
        _RESOLVERS[resource_type] = resolver
        logger.info(f"Registered resolver for resource_type: {resource_type}")

def get_resolver(resource_type: str) -> Optional[Callable]:
    """Thread-safe resolver retrieval"""
    with _resolvers_lock:
        return _RESOLVERS.get(resource_type)

# ========= ENHANCED MODULE TABLE MAPPING =========
MODULE_TABLE_CONFIG = {
    "Clients": {
        "table": "dev.Clients.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["clientID", "useriD", "client_id", "id", "ID"]
    },
    "Projects": {
        "table": "dev.Projects.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["projectID", "ProjectID", "project_id", "id", "ID"]
    },
    "Tasks": {
        "table": "dev.Tasks.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["taskID", "TaskID", "task_id", "id", "ID"]
    },
    "TimeEntries": {
        "table": "dev.TimeEntries.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["timeEntryID", "TimeEntryID", "entryID", "entry_id", "id", "ID"]
    },
    "Users": {
        "table": "dev.Users.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["userID", "UserID", "user_id", "id", "ID"]
    },
    "Employees": {
        "table": "dev.Employees.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["employeeID", "EmployeeID", "employee_id", "id", "ID"]
    },
    "Contacts": {
        "table": "dev.Contacts.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["contactID", "ContactID", "contact_id", "id", "ID"]
    },
    "Approvals": {
        "table": "dev.Approvals.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["approvalID", "ApprovalID", "approval_id", "id", "ID"]
    },
    "ProjectAssignments": {
        "table": "dev.ProjectAssignments.ddb-table",
        "owner_field": "createdBy",
        "primary_keys": ["assignmentID", "AssignmentID", "paID", "assignment_id", "id", "ID"]
    },
}

# ========= UTILITY FUNCTIONS =========
def _safe_json_log(obj: Any, max_length: int = MAX_JSON_LOG_LENGTH) -> str:
    """Safe JSON serialization for logging with length limits"""
    try:
        json_str = json.dumps(obj, default=str, separators=(',', ':'))
        return json_str if len(json_str) <= max_length else f"{json_str[:max_length]}...[truncated]"
    except Exception:
        return str(obj)[:max_length]

def _normalize_to_string_list(value: Any) -> List[str]:
    """Optimized normalization to list of strings"""
    if value is None:
        return []
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(x) for x in value if x is not None]
    return [str(value)] if value is not None else []

def _action_matches_pattern(pattern: Any, action: str) -> bool:
    """Optimized action matching with early returns"""
    if isinstance(pattern, list):
        return any(_action_matches_pattern(p, action) for p in pattern)
    pattern_str = str(pattern)
    if pattern_str == action:
        return True
    return fnmatch.fnmatch(action, pattern_str)

def _get_status(item: Dict[str, Any]) -> str:
    """Extract status with fallback logic"""
    return (item.get("Status") or item.get("status") or DEFAULT_STATUS).lower()

def _get_ov_id(item: Dict[str, Any]) -> str:
    """Extract ovID with fallback logic"""
    return str(item.get("ovID") or item.get("ovid") or item.get("SK") or "")

# ========= ENHANCED SELF-OWNED RECORDS FETCHER =========
def _get_self_owned_record_ids(user_id: str, module: str) -> Set[str]:
    """
    Enhanced fetch of record IDs owned by user for a specific module.
    Tries a self-IDs resolver first, then falls back to a scan by owner_field.
    """
    # Optional resolver (fast path): register_resolver(f"{module}__self_ids", fn)
    self_resolver = get_resolver(f"{module}__self_ids")
    if callable(self_resolver):
        try:
            ids = set(str(x) for x in (self_resolver(user_id) or []))
            if ids:
                logger.debug(f"Self resolver returned {len(ids)} IDs for {module}")
                return ids
        except Exception as e:
            logger.warning(f"Self resolver failed for {module}: {e}")

    if module not in MODULE_TABLE_CONFIG:
        logger.warning(f"No table config for module {module}")
        return set()

    config = MODULE_TABLE_CONFIG[module]
    table_name = config["table"]
    owner_field = config["owner_field"]
    primary_key_patterns = config["primary_keys"]

    try:
        table = _ddb.Table(table_name)
        self_owned_ids = set()

        scan_kwargs = {
            "FilterExpression": Attr(owner_field).eq(user_id),
            "Select": "ALL_ATTRIBUTES"
        }

        logger.debug(f"Scanning {table_name} for records owned by {user_id}")
        response = table.scan(**scan_kwargs)

        def _collect(items: List[Dict[str, Any]]):
            for item in items or []:
                record_id = None
                for pk_pattern in primary_key_patterns:
                    record_id = item.get(pk_pattern)
                    if record_id:
                        self_owned_ids.add(str(record_id))
                        break
                if not record_id:
                    logger.warning(f"No primary key found for item in {module}: {list(item.keys())[:5]}")

        _collect(response.get("Items", []))

        while response.get("LastEvaluatedKey"):
            scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            response = table.scan(**scan_kwargs)
            _collect(response.get("Items", []))

        logger.info(f"Found {len(self_owned_ids)} self-owned {module} records for user {user_id}")
        return self_owned_ids

    except Exception as e:
        logger.error(f"Error fetching self-owned {module} records for user {user_id}: {e}")
        return set()

# ========= DATA ACCESS FUNCTIONS =========
def _load_user_assignments(user_id: str) -> List[Dict[str, Any]]:
    """Optimized user assignment loading with multi-key fallback"""
    user_id_str = str(user_id)
    primary_keys = ["userID", "userId"]

    for pk_name in primary_keys:
        try:
            logger.debug(f"Querying assignments for user_id={user_id_str} with key={pk_name}")
            response = _tables["assignments"].query(
                KeyConditionExpression=Key(pk_name).eq(user_id_str)
            )
            items = response.get("Items", [])
            if items:
                logger.info(f"Loaded {len(items)} assignments for user {user_id_str}")
                return items
        except Exception as e:
            logger.warning(f"Assignment query failed for key={pk_name}: {e}")

    logger.info(f"No assignments found for user {user_id_str}")
    return []

def _load_role_by_name(role_name: str) -> Optional[Dict[str, Any]]:
    """Optimized role loading with GSI and scan fallback"""
    try:
        response = _tables["roles"].query(
            IndexName=TABLE_CONFIG["role_index"],
            KeyConditionExpression=Key("role").eq(role_name)
        )
        items = response.get("Items", [])
        if items:
            logger.debug(f"Found role '{role_name}' via GSI")
            return items[0]
    except Exception as e:
        logger.warning(f"Role GSI query failed for '{role_name}': {e}")

    try:
        logger.info(f"Falling back to scan for role '{role_name}'")
        response = _tables["roles"].scan(
            FilterExpression=Attr("role").eq(role_name)
        )
        items = response.get("Items", [])

        while response.get("LastEvaluatedKey") and not items:
            response = _tables["roles"].scan(
                FilterExpression=Attr("role").eq(role_name),
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))

        if items:
            logger.debug(f"Found role '{role_name}' via scan")
            return items[0]
    except Exception as e:
        logger.error(f"Role scan failed for '{role_name}': {e}")

    return None

# ========= RULE BUILDING =========
def _extract_role_names(assignments: List[Dict[str, Any]]) -> List[str]:
    """Extract active role names from assignments"""
    roles = []
    for assignment in assignments:
        ov_id = _get_ov_id(assignment)
        status = _get_status(assignment)
        if ov_id.startswith("A#ROLE#") and status == DEFAULT_STATUS:
            try:
                role_name = ov_id.split("#", 2)[2]
                roles.append(role_name)
            except IndexError:
                logger.warning(f"Invalid role ovID format: {ov_id}")
    return roles

def _build_rules_from_policies(policies: Dict[str, Any], module: str) -> List[Dict[str, Any]]:
    """COMPREHENSIVE: Build rules from policies with full deny pattern support"""
    
    rules = []

    def _parse_policy_section(policy_data: Any) -> Dict[str, Any]:
        """Parse policy section with JSON fallback"""
        if isinstance(policy_data, str):
            try:
                return json.loads(policy_data)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse JSON policy: {policy_data[:100]}")
                return {}
        return policy_data or {}

    def _rules_from_actions(effect: str, actions_dict: Dict[str, Any],
                            selected_ids: Dict[str, Any] = None, 
                            denied_ids: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Create rules from action definitions with comprehensive deny support"""
        rule_list = []
        for action, scope in (actions_dict or {}).items():
            # Normalize scope to list
            if isinstance(scope, str):
                scope_lower = scope.lower()
                if scope_lower in ["all", "self", "selected", "deny"]:
                    scope = [scope_lower]
                else:
                    scope = [scope]
            elif scope is True:
                scope = ["all"]
            elif scope is False or not scope:
                continue
            elif not isinstance(scope, list):
                scope = [str(scope)]

            rule = {"effect": effect, "action": action, "_entry": scope}

            # ✅ ENHANCED: Add selected IDs if scope includes "selected"
            if (selected_ids and action in selected_ids and
                isinstance(scope, list) and "selected" in [s.lower() for s in scope]):
                ids = selected_ids[action]
                if isinstance(ids, dict):
                    ids = list(ids.keys())
                elif not isinstance(ids, list):
                    ids = [str(ids)]
                rule["_selectedIds"] = [str(x) for x in ids if x]
                logger.debug(f"Setting selected IDs for {action}: {rule['_selectedIds']}")

            # ✅ COMPREHENSIVE: Add denied IDs for deny effects OR deny scopes
            if denied_ids and action in denied_ids:
                d_ids = denied_ids[action]
                if isinstance(d_ids, dict):
                    d_ids = list(d_ids.keys())
                elif not isinstance(d_ids, list):
                    d_ids = [str(d_ids)]
                
                if d_ids:
                    rule["_deniedIds"] = [str(x) for x in d_ids if x]
                    logger.debug(f"Setting denied IDs for {action}: {rule['_deniedIds']}")
                    
                    # ✅ SPECIAL: If this is an allow rule with deny scope, create separate deny rule
                    if effect == "allow" and "deny" in [s.lower() for s in scope]:
                        deny_rule = {
                            "effect": "deny",
                            "action": action,
                            "_entry": ["selected"],
                            "_selectedIds": rule["_deniedIds"],
                            "_deniedIds": rule["_deniedIds"],
                            "source": "deny_scope_expansion"
                        }
                        rule_list.append(deny_rule)

            rule_list.append(rule)
        return rule_list

    # Parse top-level policies if needed
    if isinstance(policies, str):
        try:
            policies = json.loads(policies)
        except json.JSONDecodeError:
            policies = {}

    # ✅ EXISTING: Module-specific policies first
    if module in policies:
        module_policy = _parse_policy_section(policies[module])
        allow_actions = _parse_policy_section(module_policy.get("allow"))
        deny_actions = _parse_policy_section(module_policy.get("deny"))
        selected_ids = _parse_policy_section(module_policy.get("SelectedIds"))
        denied_ids = _parse_policy_section(module_policy.get("DeniedIds"))
        
        logger.info(f"Processing {module} policy - allow: {allow_actions}, deny: {deny_actions}")
        logger.debug(f"Selected IDs: {selected_ids}, Denied IDs: {denied_ids}")
        
        # Create allow rules (may include implicit deny rules)
        rules.extend(_rules_from_actions("allow", allow_actions, selected_ids, denied_ids))
        
        # Create explicit deny rules
        rules.extend(_rules_from_actions("deny", deny_actions, selected_ids, denied_ids))

    # ✅ EXISTING: Wildcard policies second
    if "*" in policies:
        wildcard_policy = _parse_policy_section(policies["*"])
        allow_actions = _parse_policy_section(wildcard_policy.get("allow"))
        deny_actions = _parse_policy_section(wildcard_policy.get("deny"))
        selected_ids = _parse_policy_section(wildcard_policy.get("SelectedIds"))
        denied_ids = _parse_policy_section(wildcard_policy.get("DeniedIds"))
        
        rules.extend(_rules_from_actions("allow", allow_actions, selected_ids, denied_ids))
        rules.extend(_rules_from_actions("deny", deny_actions, selected_ids, denied_ids))

    # ✅ COMPREHENSIVE: Process orphaned DeniedIds (DeniedIds without explicit deny actions)
    for policy_source, policy_key in [(policies.get(module, {}), module), (policies.get("*", {}), "*")]:
        if isinstance(policy_source, str):
            try:
                policy_source = json.loads(policy_source)
            except json.JSONDecodeError:
                continue
        
        denied_ids_data = policy_source.get("DeniedIds", {})
        if isinstance(denied_ids_data, str):
            try:
                denied_ids_data = json.loads(denied_ids_data)
            except json.JSONDecodeError:
                continue
        
        if denied_ids_data:
            logger.info(f"Processing orphaned denied IDs for {policy_key}: {denied_ids_data}")
            
            for action, denied_ids in denied_ids_data.items():
                # Check if we already have explicit rules for this action
                existing_rules = [r for r in rules if r.get("action") == action]
                has_explicit_deny = any(r.get("effect") == "deny" for r in existing_rules)
                has_deny_scope = any("deny" in (r.get("_entry", []) or []) for r in existing_rules)
                
                if not has_explicit_deny and not has_deny_scope:
                    # Create orphaned deny rule
                    if isinstance(denied_ids, dict):
                        denied_id_list = list(denied_ids.keys())
                    elif isinstance(denied_ids, list):
                        denied_id_list = [str(x) for x in denied_ids]
                    else:
                        denied_id_list = [str(denied_ids)]
                    
                    if denied_id_list:
                        orphaned_deny_rule = {
                            "effect": "deny",
                            "action": action,
                            "_entry": ["selected"],
                            "_selectedIds": denied_id_list,
                            "_deniedIds": denied_id_list,
                            "source": f"orphaned_deny_{policy_key}",
                            "_orphaned": True
                        }
                        rules.append(orphaned_deny_rule)
                        logger.info(f"Created orphaned deny rule for {action}: {len(denied_id_list)} denied IDs")

    logger.info(f"Built {len(rules)} total rules for {module} (including {sum(1 for r in rules if r.get('_orphaned'))} orphaned deny rules)")
    
    return rules

# ✅ FIXED: Add missing _build_role_rules function
def _build_role_rules(role_name: str, module: str) -> List[Dict[str, Any]]:
    """Build rules from role policies with enhanced error handling"""
    role_item = _load_role_by_name(role_name)
    if not role_item or _get_status(role_item) != DEFAULT_STATUS:
        logger.warning(f"Role '{role_name}' not found or inactive")
        return []

    policies = role_item.get("Policies", {})
    if isinstance(policies, str):
        try:
            policies = json.loads(policies)
        except json.JSONDecodeError:
            policies = {}

    rules = _build_rules_from_policies(policies, module)

    for rule in rules:
        rule["source"] = f"role:{role_name}"

    logger.debug(f"Built {len(rules)} rules from role '{role_name}' for module '{module}'")
    return rules

# ========= ENHANCED CONTEXT MATCHING =========
def _context_applies(assignment: Dict[str, Any], target_ctx: Dict[str, Any]) -> bool:
    """
    Context matching for overrides & embedded entries.
    - Status must be active (and not expired if ExpiresAt present)
    - Module must match
    - RECORD applies only to the exact ContextId == target_ctx.recordId
    - GLOBAL / RECORD_SET apply to module-level ops
    """
    try:
        if _get_status(assignment) != DEFAULT_STATUS:
            return False

        # Optional expiry guard
        exp = assignment.get("expiresAt") or assignment.get("ExpiresAt")
        if exp:
            try:
                dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                if dt < datetime.now(timezone.utc):
                    return False
            except Exception:
                pass

        assignment_module = (assignment.get("module") or "").lower()
        target_module = (target_ctx.get("module") or "").lower()
        if not assignment_module or assignment_module != target_module:
            return False

        ctx_type = (assignment.get("contextType") or "").upper()
        if ctx_type in {"GLOBAL", "RECORD_SET", ""}:
            return True
        if ctx_type == "RECORD":
            return str(assignment.get("ContextId") or assignment.get("contextId") or "") == str(target_ctx.get("recordId") or "")
        return False
    except Exception as e:
        logger.error(f"Error in context matching: {e}")
        return False

# ✅ FIXED: Corrected function name and comprehensive implementation
def _evaluate_combined_scopes(user_id: str, module: str, action: str, rules: List[Dict]) -> Dict[str, Any]:
    """COMPREHENSIVE: Handle all patterns including deny-only scenarios with proper precedence"""
    
    allow_all = False
    allow_ids = set()
    deny_all = False
    deny_ids = set()
    active_scopes = []
    has_deny_pattern = False
    has_allow_pattern = False

    logger.debug(f"Evaluating {len(rules)} rules for {user_id}.{module}.{action}")

    # Process all rules
    for rule in rules:
        if not _action_matches_pattern(rule.get("action", "*"), action):
            continue

        scope = rule.get("_entry")
        effect = rule.get("effect", "").lower()
        selected_ids = rule.get("_selectedIds", [])
        denied_ids_from_rule = rule.get("_deniedIds", [])

        # Normalize scope
        if scope is True:
            scope_list = ["all"]
        elif isinstance(scope, list):
            scope_list = scope
        elif isinstance(scope, str):
            scope_list = [scope]
        else:
            continue

        logger.debug(f"Processing rule: effect={effect}, scopes={scope_list}, selectedIds={len(selected_ids)}, deniedIds={len(denied_ids_from_rule)}")

        for scope_type in scope_list:
            scope_type = str(scope_type).lower()

            if effect == "deny":
                has_deny_pattern = True
                if scope_type == "all":
                    deny_all = True
                    logger.debug("Applied deny-all rule")
                elif scope_type == "selected":
                    deny_ids.update(str(x) for x in (selected_ids or []))
                    logger.debug(f"Applied deny for {len(selected_ids or [])} selected IDs")
                elif scope_type == "self":
                    self_owned = _get_self_owned_record_ids(user_id, module)
                    deny_ids.update(self_owned)
                    logger.debug(f"Applied deny for {len(self_owned)} self-owned records")
                elif scope_type == "deny":
                    # Explicit deny scope - process denied IDs
                    if denied_ids_from_rule:
                        deny_ids.update(str(x) for x in denied_ids_from_rule)
                        logger.debug(f"Applied explicit deny for {len(denied_ids_from_rule)} IDs")

            elif effect == "allow":
                has_allow_pattern = True
                if scope_type == "all":
                    allow_all = True
                    if "all" not in active_scopes:
                        active_scopes.append("all")
                    logger.debug("Applied allow-all rule")
                elif scope_type == "selected":
                    allow_ids.update(str(x) for x in (selected_ids or []))
                    if "selected" not in active_scopes:
                        active_scopes.append("selected")
                    logger.debug(f"Applied allow for {len(selected_ids or [])} selected IDs")
                elif scope_type == "self":
                    self_owned = _get_self_owned_record_ids(user_id, module)
                    allow_ids.update(self_owned)
                    if "self" not in active_scopes:
                        active_scopes.append("self")
                    logger.debug(f"Applied allow for {len(self_owned)} self-owned records")
                elif scope_type == "deny":
                    # ✅ COMPREHENSIVE: Allow with deny scope means "all except denied"
                    allow_all = True
                    has_deny_pattern = True
                    if "all" not in active_scopes:
                        active_scopes.append("all")
                    if "deny" not in active_scopes:
                        active_scopes.append("deny")
                    # Process the denied IDs
                    if denied_ids_from_rule:
                        deny_ids.update(str(x) for x in denied_ids_from_rule)
                        logger.debug(f"Applied allow-all with {len(denied_ids_from_rule)} denied IDs")

        # ✅ COMPREHENSIVE: Always process denied IDs from rules
        if denied_ids_from_rule:
            deny_ids.update(str(x) for x in denied_ids_from_rule)
            has_deny_pattern = True
            if "deny" not in active_scopes:
                active_scopes.append("deny")

    # Apply deny-wins logic with comprehensive pattern detection
    if deny_all:
        logger.info(f"Access denied (deny-all) for {user_id}.{module}.{action}")
        return {"all": False, "ids": set(), "scopes": [], "denied": "all", "pattern": "none"}

    if allow_all:
        if deny_ids or has_deny_pattern:
            logger.info(f"Allow-all with {len(deny_ids)} denied IDs for {user_id}.{module}.{action}")
            return {
                "all": True, 
                "denied_ids": deny_ids, 
                "scopes": active_scopes,
                "pattern": "all_except_denied",
                "stats": {
                    "totalDenied": len(deny_ids),
                    "hasAllAccess": True
                }
            }
        logger.info(f"Allow-all access for {user_id}.{module}.{action}")
        return {
            "all": True, 
            "ids": None, 
            "denied_ids": set(),
            "scopes": active_scopes,
            "pattern": "all"
        }

    # ✅ COMPREHENSIVE: Handle deny-only patterns (deny specific, allow others)
    if has_deny_pattern and not has_allow_pattern and deny_ids:
        logger.info(f"Deny-only pattern: allowing all except {len(deny_ids)} denied IDs for {user_id}.{module}.{action}")
        return {
            "all": True,
            "denied_ids": deny_ids,
            "scopes": active_scopes or ["deny"],
            "pattern": "all_except_denied",
            "stats": {
                "totalDenied": len(deny_ids),
                "denyOnlyPattern": True
            }
        }

    # Specific access with potential denies
    final_ids = allow_ids - deny_ids
    pattern = "specific_with_precedence" if (deny_ids or has_deny_pattern) else "specific"
    
    logger.info(f"Specific access for {user_id}.{module}.{action}: {len(allow_ids)} allowed, {len(deny_ids)} denied, {len(final_ids)} final")
    
    return {
        "all": False, 
        "ids": final_ids, 
        "scopes": active_scopes, 
        "denied_ids": deny_ids,
        "pattern": pattern,
        "stats": {
            "totalAllowed": len(allow_ids),
            "totalDenied": len(deny_ids),
            "finalAllowed": len(final_ids),
            "deniedFromAllowed": len(allow_ids & deny_ids)
        }
    }

# ========= RULE GATHERING (UNIFIED PIPELINE) =========
def _extract_action_ids(ids_data: Dict, action: str) -> Set[str]:
    """
    Extract IDs for a specific action from SelectedIds or DeniedIds structure.
    Supports both action-specific and general structures.
    """
    if not ids_data:
        return set()

    # Try action-specific first
    if action in ids_data:
        ids = ids_data[action]
        if isinstance(ids, dict):
            return set(str(k) for k in ids.keys())
        elif isinstance(ids, list):
            return set(str(x) for x in ids)
        else:
            return {str(ids)}

    # Fallback to general structure (collect all IDs)
    if isinstance(ids_data, dict):
        all_ids = set()
        for key, value in ids_data.items():
            if isinstance(value, dict):
                all_ids.update(str(k) for k in value.keys())
            elif isinstance(value, list):
                all_ids.update(str(x) for x in value)
            else:
                all_ids.add(str(value))
        return all_ids

    return set()

def _gather_rules_for_action(user_id: str, module: str, action: str, assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect rules from roles + overrides + embedded with comprehensive deny support"""
    rules: List[Dict[str, Any]] = []

    # Roles
    role_names = _extract_role_names(assignments)
    for role_name in role_names:
        for r in _build_role_rules(role_name, module):
            if _action_matches_pattern(r.get("action", "*"), action):
                r["source"] = r.get("source") or f"role:{role_name}"
                rules.append(r)

    # Overrides & embedded (per-user)
    target_ctx = {"module": module}
    for a in assignments:
        ov = _get_ov_id(a)
        is_override = ov.startswith("B#OVR#")
        is_role_embedded = ov.startswith("A#ROLE#")
        if is_override and not _context_applies(a, target_ctx):
            continue

        allow_data = a.get("Allow") or a.get("AllowJSON") or a.get("allow") or {}
        deny_data  = a.get("Deny")  or a.get("DenyJSON")  or a.get("deny")  or {}
        if isinstance(allow_data, str):
            try: allow_data = json.loads(allow_data)
            except json.JSONDecodeError: allow_data = {}
        if isinstance(deny_data, str):
            try: deny_data = json.loads(deny_data)
            except json.JSONDecodeError: deny_data = {}

        # Unnest per-module if present
        if isinstance(allow_data.get(module), dict):
            allow_data = allow_data[module].get("allow", allow_data[module])
        if isinstance(deny_data.get(module), dict):
            deny_data = deny_data[module].get("deny", deny_data[module])

        selected_ids = a.get("SelectedIds") or {}
        denied_ids   = a.get("DeniedIds") or {}
        src = "override" if is_override else ("embedded" if is_role_embedded else "user")

        # Allow rule
        scope = allow_data.get(action)
        if scope:
            scope = scope if isinstance(scope, list) else [scope]
            rule = {"effect": "allow", "action": action, "_entry": scope, "source": src}
            sids = _extract_action_ids(selected_ids, action)
            dids = _extract_action_ids(denied_ids, action)
            if sids and ("selected" in [str(s).lower() for s in scope]):
                rule["_selectedIds"] = list(sids)
            if dids:
                rule["_deniedIds"] = list(dids)
            rules.append(rule)

        # Deny rule
        dscope = deny_data.get(action)
        if dscope:
            dscope = dscope if isinstance(dscope, list) else [dscope]
            drule = {"effect": "deny", "action": action, "_entry": dscope, "source": src}
            dids = _extract_action_ids(denied_ids, action)
            sids = _extract_action_ids(selected_ids, action)
            if dids and ("selected" in [str(s).lower() for s in dscope]):
                drule["_selectedIds"] = list(dids)
            if dids:
                drule["_deniedIds"] = list(dids)
            rules.append(drule)

        # ✅ COMPREHENSIVE: Handle orphaned denied IDs (DeniedIds without explicit deny actions)
        if denied_ids:
            action_denied_ids = _extract_action_ids(denied_ids, action)
            if action_denied_ids:
                # Check if we already have rules that handle these denied IDs
                has_relevant_rule = any(
                    rule.get("action") == action and 
                    (rule.get("_deniedIds") or "deny" in (rule.get("_entry", []) or []))
                    for rule in rules
                )
                
                if not has_relevant_rule:
                    # Create orphaned deny rule
                    orphaned_rule = {
                        "effect": "deny",
                        "action": action,
                        "_entry": ["selected"],
                        "_selectedIds": list(action_denied_ids),
                        "_deniedIds": list(action_denied_ids),
                        "source": f"{src}_orphaned",
                        "_orphaned": True
                    }
                    rules.append(orphaned_rule)
                    logger.debug(f"Created orphaned deny rule for {action}: {len(action_denied_ids)} IDs")

    logger.debug(f"Gathered {len(rules)} rules for {user_id}.{module}.{action}")
    return rules

def _split_override_role_rules(rules: List[Dict[str, Any]]):
    """Split rules by source type for precedence handling"""
    overrides = [r for r in rules if r.get("source") == "override"]
    roles     = [r for r in rules if str(r.get("source","")).startswith("role:")]
    others    = [r for r in rules if r.get("source") not in {"override"} and not str(r.get("source","")).startswith("role:")]
    return overrides, roles, others

# ========= CORE API FUNCTIONS =========
@dataclass
class AccessRequest:
    user: Dict[str, Any]
    resourceType: str
    action: str
    targetCtx: Optional[Dict[str, Any]] = None
    resource: Optional[Dict[str, Any]] = None
    resourceId: Optional[str] = None
    env: Optional[Dict[str, Any]] = None

def evaluate(request: AccessRequest) -> Dict[str, Any]:
    """Unified evaluation with deny-wins + override precedence"""
    user_id = request.user.get("id")
    if not user_id:
        logger.warning("Access denied: missing user ID")
        return {"decision": "DENY", "reason": "Missing user ID", "matched": None}

    target = request.targetCtx or {}
    target.setdefault("module", request.resourceType)

    logger.info(f"Evaluating access: user={user_id}, resource={request.resourceType}, action={request.action}")

    try:
        assignments = _load_user_assignments(user_id)
        if not assignments:
            logger.info(f"No assignments found for user {user_id}")
            return {"decision": "DENY", "reason": "No user assignments", "matched": None}
    except Exception as e:
        logger.error(f"Failed to load assignments for user {user_id}: {e}")
        return {"decision": "DENY", "reason": f"Assignment load error: {e}", "matched": None}

    # Gather rules and apply override precedence
    all_rules = _gather_rules_for_action(user_id, request.resourceType, request.action, assignments)
    overrides, roles, others = _split_override_role_rules(all_rules)
    effective_rules = overrides if overrides else (roles + others)

    result = _evaluate_combined_scopes(user_id, request.resourceType, request.action, effective_rules)

    # Map scope result to ALLOW/DENY for the action (module-level)
    if result.get("denied") == "all":
        return {"decision": "DENY", "reason": None, "matched": {"source": "deny_all"}}

    if result.get("all"):
        return {"decision": "ALLOW", "reason": None, "matched": {"source": "allow_all"}}

    # If we have any specific scope (selected/self) or specific IDs, allow at action level;
    # record-level filtering happens via get_allowed_record_ids / can_access_record.
    if result.get("ids") or any(s in (result.get("scopes") or []) for s in ["self", "selected"]):
        return {"decision": "ALLOW", "reason": None, "matched": {"source": "scoped"}}

    return {"decision": "DENY", "reason": "No matching allow rule", "matched": None}

def can_do(user_id: str, module: str, action: str, *,
           record_id: Optional[str] = None, record_type: Optional[str] = None,
           extra_ctx: Optional[Dict] = None) -> bool:
    """Enhanced permission check with detailed context"""
    target_ctx = {"module": module}
    if record_type:
        target_ctx["recordType"] = record_type
    if record_id:
        target_ctx["recordId"] = record_id
    if extra_ctx:
        target_ctx.update(extra_ctx)

    decision = evaluate(AccessRequest(
        user={"id": str(user_id)},
        resourceType=module,
        action=action,
        targetCtx=target_ctx,
        resourceId=record_id,
    ))
    result = decision.get("decision") == "ALLOW"
    logger.debug(f"can_do({user_id}, {module}, {action}, {record_id}) = {result}")
    return result

def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
    """
    COMPREHENSIVE: Handle all edge cases including mixed allow/deny patterns.
    Override precedence: if any override rules exist for the action, they fully replace role rules.
    """
    try:
        assignments = _load_user_assignments(user_id)
        if not assignments:
            return {"all": False, "ids": set(), "scopes": [], "denied_ids": set(), "pattern": "none"}

        logger.info(f"Processing permissions for user {user_id}, module {module}, action {action}")

        all_rules = _gather_rules_for_action(user_id, module, action, assignments)
        overrides, roles, others = _split_override_role_rules(all_rules)
        effective = overrides if overrides else (roles + others)

        result = _evaluate_combined_scopes(user_id, module, action, effective)

        # Normalize pattern for consumers
        if result.get("denied") == "all":
            result["pattern"] = "none"
            result.setdefault("denied_ids", set())
            result["ids"] = set()
            result["all"] = False
            result["scopes"] = []
            return result

        if result.get("all") and result.get("denied_ids"):
            result["pattern"] = "all_except_denied"
        elif result.get("all"):
            result["pattern"] = "all"
            result.setdefault("denied_ids", set())
        else:
            denied_ids = result.get("denied_ids", set())
            result["pattern"] = "specific_with_precedence" if denied_ids else "specific"
            result.setdefault("ids", set())
            result.setdefault("denied_ids", set())
        
        return result

    except Exception as e:
        logger.error(f"Error in get_allowed_record_ids: {e}")
        return {"all": False, "ids": set(), "scopes": [], "denied_ids": set(), "pattern": "error"}

def can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
    """
    COMPREHENSIVE: Check if user can access a specific record (DENY > ALLOW)
    """
    try:
        scope_result = get_allowed_record_ids(user_id, module, action)
        record_id_str = str(record_id)

        # Step 1: Check DENY first (highest precedence)
        denied_ids = scope_result.get("denied_ids", set())
        if record_id_str in denied_ids:
            logger.debug(f"❌ Access DENIED for {record_id}: explicitly denied")
            return False

        # Step 2: Check ALLOW patterns
        if scope_result.get("all", False):
            logger.debug(f"✅ Access GRANTED for {record_id}: all access (not denied)")
            return True

        # Step 3: Check specific allowed IDs
        allowed_ids = scope_result.get("ids", set())
        is_allowed = record_id_str in allowed_ids
        logger.debug(f"{'✅' if is_allowed else '❌'} Access {'GRANTED' if is_allowed else 'DENIED'} for {record_id}: {'in' if is_allowed else 'not in'} allowed list")
        return is_allowed

    except Exception as e:
        logger.error(f"Error checking record access for {record_id}: {e}")
        return False

def get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
    """
    COMPREHENSIVE: Get filter criteria for database queries
    Supports all patterns: all, all_except_denied, specific, specific_with_precedence
    """
    try:
        scope_result = get_allowed_record_ids(user_id, module, action)

        pattern = scope_result.get("pattern", "none")
        scopes = scope_result.get("scopes", [])

        if pattern == "all":
            return {"type": "all", "scopes": scopes, "pattern": pattern}

        elif pattern == "all_except_denied":
            denied_ids = scope_result.get("denied_ids", set())
            return {
                "type": "all_except_denied",
                "denied_ids": list(denied_ids),
                "scopes": scopes,
                "pattern": pattern,
                "stats": scope_result.get("stats", {})
            }

        elif pattern in ["specific", "specific_with_precedence"]:
            allowed_ids = scope_result.get("ids", set())
            denied_ids = scope_result.get("denied_ids", set())
            result = {
                "type": "specific",
                "allowed_ids": list(allowed_ids),
                "scopes": scopes,
                "pattern": pattern
            }
            if denied_ids and pattern == "specific_with_precedence":
                result["denied_ids"] = list(denied_ids)
                result["stats"] = scope_result.get("stats", {})
            return result

        else:
            return {"type": "none", "scopes": [], "pattern": "none"}

    except Exception as e:
        logger.error(f"Error getting accessible records filter: {e}")
        return {"type": "none", "scopes": [], "pattern": "error", "error": str(e)}

# ========= ADDITIONAL UTILITY FUNCTIONS =========
def get_user_scopes_summary(user_id: str, module: str) -> Dict[str, Any]:
    """Get a summary of all scopes for a user on a module"""
    try:
        assignments = _load_user_assignments(user_id)
        role_names = _extract_role_names(assignments)

        summary = {
            "user_id": user_id,
            "module": module,
            "roles": role_names,
            "has_overrides": False,
            "actions": {}
        }

        common_actions = ["view", "create", "modify", "delete", "approve"]
        for action in common_actions:
            scope_result = get_allowed_record_ids(user_id, module, action)
            summary["actions"][action] = {
                "allowed": scope_result.get("all", False) or bool(scope_result.get("ids")),
                "scope_type": "all" if scope_result.get("all", False) else "specific",
                "scopes": scope_result.get("scopes", []),
                "pattern": scope_result.get("pattern", "none"),
                "record_count": len(scope_result.get("ids", set())) if not scope_result.get("all", False) else "unlimited",
                "denied_count": len(scope_result.get("denied_ids", set()))
            }

        for assignment in assignments:
            ov_id = _get_ov_id(assignment)
            if ov_id.startswith("B#OVR#"):
                summary["has_overrides"] = True
                break

        return summary

    except Exception as e:
        logger.error(f"Error getting user scopes summary: {e}")
        return {"error": str(e)}

def get_user_permissions_debug(user_id: str, module: str) -> Dict[str, Any]:
    """
    DEBUG: Get comprehensive permissions breakdown for debugging
    """
    try:
        debug_info = {
            "user_id": user_id,
            "module": module,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "actions": {}
        }

        for action in ["view", "create", "modify", "delete"]:
            scope_result = get_allowed_record_ids(user_id, module, action)
            filter_result = get_accessible_records_filter(user_id, module, action)
            debug_info["actions"][action] = {
                "scope_result": scope_result,
                "filter_result": filter_result,
                "pattern": scope_result.get("pattern", "unknown"),
                "scopes": scope_result.get("scopes", []),
                "stats": scope_result.get("stats", {})
            }
        return debug_info

    except Exception as e:
        logger.error(f"Error getting debug permissions: {e}")
        return {"error": str(e)}

# Helper function for role data loading
def _load_role_data(role_name: str) -> Dict[str, Any]:
    """Load role data (compat wrapper around _load_role_by_name)"""
    try:
        item = _load_role_by_name(role_name)
        return item or {}
    except Exception as e:
        logger.error(f"Error loading role data for {role_name}: {e}")
        return {}

# ========= LEGACY COMPATIBILITY FUNCTIONS =========
def _process_override_action_comprehensive(assignment: Dict[str, Any], action: str, user_id: str, module: str) -> Dict[str, Any]:
    """
    LEGACY COMPATIBILITY: Process a single override item for an action.
    Use get_allowed_record_ids for new code.
    """
    try:
        allow_data = assignment.get("Allow", {})
        selected_ids_data = assignment.get("SelectedIds", {})
        denied_ids_data = assignment.get("DeniedIds", {})

        if isinstance(allow_data, str):
            allow_data = json.loads(allow_data)

        scope_list = allow_data.get(action, [])
        if isinstance(scope_list, str):
            scope_list = [scope_list]

        allow_all = False
        allow_ids = set()
        denied_ids = set()
        active_scopes = []

        for scope_type in scope_list:
            scope_type = str(scope_type).lower()
            if scope_type == "all":
                allow_all = True
                if "all" not in active_scopes:
                    active_scopes.append("all")
            elif scope_type == "selected":
                selected_for_action = _extract_action_ids(selected_ids_data, action)
                allow_ids.update(selected_for_action)
                if "selected" not in active_scopes:
                    active_scopes.append("selected")
            elif scope_type == "self":
                self_owned = _get_self_owned_record_ids(user_id, module)
                allow_ids.update(self_owned)
                if "self" not in active_scopes:
                    active_scopes.append("self")
            elif scope_type == "deny":
                if "deny" not in active_scopes:
                    active_scopes.append("deny")

        # Process denied IDs
        if "deny" in [str(s).lower() for s in scope_list] or denied_ids_data:
            denied_for_action = _extract_action_ids(denied_ids_data, action)
            denied_ids.update(denied_for_action)

        if allow_all:
            if denied_ids:
                return {
                    "all": True,
                    "ids": None,
                    "denied_ids": denied_ids,
                    "scopes": active_scopes,
                    "pattern": "all_except_denied",
                    "stats": {"totalDenied": len(denied_ids), "hasAllAccess": True}
                }
            else:
                return {
                    "all": True,
                    "ids": None,
                    "denied_ids": set(),
                    "scopes": active_scopes,
                    "pattern": "all"
                }
        else:
            final_allowed = allow_ids - denied_ids
            return {
                "all": False,
                "ids": final_allowed,
                "denied_ids": denied_ids,
                "scopes": active_scopes,
                "pattern": "specific_with_precedence" if denied_ids else "specific",
                "stats": {
                    "totalAllowed": len(allow_ids),
                    "totalDenied": len(denied_ids),
                    "finalAllowed": len(final_allowed),
                    "deniedFromAllowed": len(allow_ids & denied_ids)
                }
            }

    except Exception as e:
        logger.error(f"Error processing override action: {e}")
        return {"all": False, "ids": set(), "scopes": [], "denied_ids": set()}

def _process_role_permissions_comprehensive(user_id: str, module: str, action: str, assignments: List[Dict]) -> Dict[str, Any]:
    """
    LEGACY COMPATIBILITY: Role permissions aggregator.
    Use get_allowed_record_ids for new code.
    """
    try:
        role_names = _extract_role_names(assignments)
        combined_allow_all = False
        combined_allow_ids = set()
        combined_denied_ids = set()
        combined_scopes = []

        for role_name in role_names:
            role_data = _load_role_data(role_name)
            if not role_data:
                continue

            policies = (role_data.get("Policies", {}) or {})
            if isinstance(policies, str):
                try:
                    policies = json.loads(policies)
                except json.JSONDecodeError:
                    policies = {}

            role_mod = policies.get(module, {})
            allow_rules = (role_mod.get("allow", {}) or {}).get(action, [])

            if isinstance(allow_rules, str):
                allow_rules = [allow_rules]

            for scope_type in allow_rules:
                scope_type = str(scope_type).lower()
                if scope_type == "all":
                    combined_allow_all = True
                    if "all" not in combined_scopes:
                        combined_scopes.append("all")
                elif scope_type == "selected":
                    selected_ids = (role_mod.get("SelectedIds", {}) or {}).get(action, {})
                    if isinstance(selected_ids, dict):
                        combined_allow_ids.update(selected_ids.keys())
                    elif isinstance(selected_ids, list):
                        combined_allow_ids.update(str(x) for x in selected_ids)
                    if "selected" not in combined_scopes:
                        combined_scopes.append("selected")
                elif scope_type == "self":
                    self_owned = _get_self_owned_record_ids(user_id, module)
                    combined_allow_ids.update(self_owned)
                    if "self" not in combined_scopes:
                        combined_scopes.append("self")

            # Denies in role
            denied_ids = (role_mod.get("DeniedIds", {}) or {}).get(action, {})
            if isinstance(denied_ids, dict):
                combined_denied_ids.update(denied_ids.keys())
            elif isinstance(denied_ids, list):
                combined_denied_ids.update(str(x) for x in denied_ids)

        if combined_allow_all:
            if combined_denied_ids:
                return {
                    "all": True,
                    "ids": None,
                    "denied_ids": combined_denied_ids,
                    "scopes": combined_scopes,
                    "pattern": "all_except_denied"
                }
            else:
                return {
                    "all": True,
                    "ids": None,
                    "denied_ids": set(),
                    "scopes": combined_scopes,
                    "pattern": "all"
                }
        else:
            final_allowed = combined_allow_ids - combined_denied_ids
            return {
                "all": False,
                "ids": final_allowed,
                "denied_ids": combined_denied_ids,
                "scopes": combined_scopes,
                "pattern": "specific_with_precedence" if combined_denied_ids else "specific"
            }

    except Exception as e:
        logger.error(f"Error processing role permissions: {e}")
        return {"all": False, "ids": set(), "scopes": [], "denied_ids": set()}

def module_allow_all(user_id: str, module: str, action: str) -> Dict[str, Any]:
    """
    Helper that returns an 'allow all' pattern structure.
    Kept to satisfy existing imports/tests that expect this symbol.
    """
    return {"all": True, "ids": None, "denied_ids": set(), "scopes": ["all"], "pattern": "all"}

# ========= MODULE EXPORTS =========
__all__ = [
    "AccessRequest", "evaluate", "can_do", "module_allow_all",
    "get_allowed_record_ids", "can_access_record", "get_accessible_records_filter",
    "get_user_scopes_summary", "get_user_permissions_debug", "register_resolver", "get_resolver"
]

# ========= INITIALIZATION LOG =========
logger.info("✅ Enhanced Policy Engine initialized successfully")
logger.info(f"Configured modules: {list(MODULE_TABLE_CONFIG.keys())}")
logger.info(f"Log level: {_LOG_LEVEL}")