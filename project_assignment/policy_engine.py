from __future__ import annotations
import os
import fnmatch
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable
from boto3.dynamodb.conditions import Key, Attr
import boto3


# ——— DynamoDB Table Setup ———
USER_ASSIGNMENTS_TABLE_NAME = os.environ.get("USER_ASSIGNMENTS_TABLE", "dev.UserGrants.ddb-table")
ROLE_POLICIES_TABLE_NAME = os.environ.get("ROLE_POLICIES_TABLE", "dev.roles_t.ddb-table")
POLICY_DEFINITIONS_TABLE_NAME = os.environ.get("POLICY_DEFINITIONS_TABLE", "dev.PolicyDefinitions.ddb-table")

dynamodb_resource = boto3.resource("dynamodb")
user_assignments_table = dynamodb_resource.Table(USER_ASSIGNMENTS_TABLE_NAME)
role_policies_table = dynamodb_resource.Table(ROLE_POLICIES_TABLE_NAME)
policy_definitions_table = dynamodb_resource.Table(POLICY_DEFINITIONS_TABLE_NAME)


# ——— Resolver Registry ———
resource_resolvers: Dict[str, Callable[[str], Dict[str, Any]]] = {}

def register_resource_resolver(resource_type: str, resolver_function: Callable[[str], Dict[str, Any]]) -> None:
    """Register a resolver function for a resource type."""
    resource_resolvers[resource_type] = resolver_function


# ——— Utility Helpers ———
def normalize_to_string_list(value) -> List[str]:
    """Normalize a value into a list of strings (handles lists, tuples, sets, comma-separated strings)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    string_value = str(value).strip()
    if not string_value:
        return []
    return [item.strip() for item in string_value.split(",") if item.strip()]


def check_action_pattern_match(rule_action_pattern: Any, requested_action: str) -> bool:
    """Match action names with support for wildcards (e.g., view, export:*)."""
    if isinstance(rule_action_pattern, list):
        return any(check_action_pattern_match(action, requested_action) for action in rule_action_pattern)
    return fnmatch.fnmatch(requested_action, str(rule_action_pattern))


def parse_as_object(raw_data):
    """Safely parse JSON strings into dicts; return {} if invalid."""
    if isinstance(raw_data, str):
        try:
            return json.loads(raw_data)
        except Exception:
            return {}
    return raw_data or {}


# ——— Get Policies for User API ———
def load_user_assignment_records(user_identifier: str) -> List[Dict[str, Any]]:
    """Fetch user assignment/override records from DynamoDB (handles casing for PK)."""
    items = []
    for pk in ["userID", "userId"]:  # handle casing
        try:
            resp = user_assignments_table.query(KeyConditionExpression=Key(pk).eq(str(user_identifier)))
            items.extend(resp.get("Items", []) or [])
        except Exception:
            pass
    return items


def load_role_record_by_role_name(role_name: str) -> Optional[Dict[str, Any]]:
    """Fetch role record from roles_t by role name (query index first, fallback to scan)."""
    role_index_name = os.environ.get("ROLE_BY_NAME_INDEX", "role-rid-index")

    # Try index query
    try:
        resp = role_policies_table.query(
            IndexName=role_index_name,
            KeyConditionExpression=Key("role").eq(role_name)
        )
        items = resp.get("Items", []) or []
        if items:
            return items[0]
    except Exception:
        pass

    # Fallback: scan
    try:
        resp = role_policies_table.scan(FilterExpression=Attr("role").eq(role_name))
        items = resp.get("Items", []) or []
        if items:
            return items[0]
    except Exception:
        pass

    return None


# ——— Rules Conversion (Allow / Deny) ———
def convert_permissions_dict_to_rules(effect: str, permissions_dict: dict, selected_ids: dict = None) -> List[Dict[str, Any]]:
    """
    Convert allow/deny dict into normalized rules.

    Supported scopes:
      - "all" → access to all records
      - "self" → records owned/assigned to the user
      - "selected" → record-level access via SelectedIds
      - "selected_by_creator" → records assigned by specific users
    """
    rules = []
    for action, value in (permissions_dict or {}).items():
        rule = {"effect": effect, "action": action}
        selected_record_ids = None
        selected_creator_ids = None

        # Normalize values
        if isinstance(value, str):
            value = ["all"] if value.lower() == "all" else [value]
        elif isinstance(value, list):
            value = [str(v) for v in value]
        elif isinstance(value, dict):
            if "selected" in value:
                selected_record_ids = normalize_to_string_list(value.get("selected"))
                value = ["selected"]
            elif "selected_by_creator" in value:
                selected_creator_ids = normalize_to_string_list(value.get("selected_by_creator"))
                value = ["selected_by_creator"]
            else:
                value = list(value.keys())

        rule["_entry"] = value

        # Attach selected record IDs
        if selected_record_ids:
            rule["_selectedIds"] = selected_record_ids
        elif selected_ids and action in selected_ids:
            ids_dict = selected_ids[action]
            rule["_selectedIds"] = list(map(str, ids_dict.keys())) if isinstance(ids_dict, dict) else normalize_to_string_list(ids_dict)

        # Attach selected creators (for selected_by_creator)
        if selected_creator_ids:
            rule["_selectedCreators"] = selected_creator_ids
        elif selected_ids and "SelectedCreators" in selected_ids and action in selected_ids["SelectedCreators"]:
            creators_dict = selected_ids["SelectedCreators"][action]
            rule["_selectedCreators"] = list(map(str, creators_dict.keys())) if isinstance(creators_dict, dict) else normalize_to_string_list(creators_dict)

        rules.append(rule)
    return rules


def extract_role_permission_rules_for_module(role_name: str, target_module: str) -> List[Dict[str, Any]]:
    """Extract normalized role policies for a given module (from roles_t table)."""
    record = load_role_record_by_role_name(role_name)
    if not record or str(record.get("Status", "active")).lower() != "active":
        return []

    policies = record.get("Policies")
    if isinstance(policies, str):
        try:
            policies = json.loads(policies)
        except Exception:
            policies = {}

    rules: List[Dict[str, Any]] = []

    # Wildcard module rules (* applies to all modules)
    if isinstance(policies, dict) and "*" in policies:
        wild = parse_as_object(policies["*"])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(wild.get("allow")), parse_as_object(wild)))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(wild.get("deny")), parse_as_object(wild)))

    # Specific module rules
    if isinstance(policies, dict) and target_module in policies:
        mod = parse_as_object(policies[target_module])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(mod.get("allow")), parse_as_object(mod)))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(mod.get("deny")), parse_as_object(mod)))

    return rules


# ——— Rule Evaluation ———
def check_permission_entry_matches(entry: Any, user: Dict[str, Any], target: Dict[str, Any],
                                   resource: Optional[Dict[str, Any]],
                                   selected_ids: Optional[List[str]] = None,
                                   selected_creators: Optional[List[str]] = None,
                                   effect: str = "allow", action: str = "") -> bool:
    """Check if a rule entry matches the given request (deny > allow)."""
    uid = user.get("id")
    record_id = target.get("recordId")

    if entry is True:
        return True
    if not entry:
        return False

    if isinstance(entry, list):
        allowed = False
        for scope in entry:
            # All records
            if scope == "all":
                return True

            # Self records (user is assignee, creator, or owner)
            if scope == "self" and resource:
                if resource.get("createdBy") == uid or resource.get("ownerUserId") == uid \
                   or resource.get("assignedTo") == uid or resource.get("assignedBy") == uid:
                    allowed = True

            # Specific records by ID
            if scope == "selected":
                target_id = uid if action == "create" else record_id
                if target_id and selected_ids:
                    in_selected = str(target_id) in set(map(str, selected_ids))
                    if effect.lower() == "allow" and in_selected:
                        allowed = True
                    if effect.lower() == "deny" and in_selected:
                        return True  # deny wins

            # Records created by specific users
            if scope == "selected_by_creator" and resource:
                creator_id = resource.get("assignedBy") 
                if creator_id and selected_creators:
                    in_selected = str(creator_id) in set(map(str, selected_creators))
                    if effect.lower() == "allow" and in_selected:
                        allowed = True
                    if effect.lower() == "deny" and in_selected:
                        return True  # deny wins

        return allowed

    return False


# ——— Request Wrapper ———
@dataclass
class AccessRequest:
    user: Dict[str, Any]
    resourceType: str
    action: str
    targetCtx: Optional[Dict[str, Any]] = None
    resource: Optional[Dict[str, Any]] = None
    resourceId: Optional[str] = None


# ——— Main Evaluate Function ———
def evaluate(req: AccessRequest) -> Dict[str, Any]:
    """Evaluate an access request against roles + overrides. Deny takes precedence over allow."""
    uid = req.user.get("id")
    module = req.resourceType
    action = req.action

    # Default context always includes module
    target = req.targetCtx or {"module": module}
    target.setdefault("module", module)

    # Load user assignment rows (roles + overrides)
    assignments = load_user_assignment_records(str(uid))
    override_rules: List[Dict[str, Any]] = []
    role_names: List[str] = []

    for rec in assignments:
        ovID = str(rec.get("ovID") or rec.get("SK") or "")
        status = rec.get("Status") or rec.get("status") or "active"

        if status != "active":
            continue

        # Module-specific overrides
        if ovID.startswith("B#OVR#") and rec.get("module") == module:
            allow = rec.get("Allow") or {}
            deny = rec.get("Deny") or {}
            override_rules.extend(convert_permissions_dict_to_rules("allow", allow, rec))
            override_rules.extend(convert_permissions_dict_to_rules("deny", deny, rec))

        # Role assignment
        elif ovID.startswith("A#ROLE#"):
            role_names.append(ovID.split("#", 2)[2])

    # Load role-based rules
    role_rules: List[Dict[str, Any]] = []
    for role in role_names:
        role_rules.extend(extract_role_permission_rules_for_module(role, module))

    # Merge role rules + overrides (overrides win)
    combined_rules: List[Dict[str, Any]] = []
    if override_rules:
        override_actions = {rule["action"] for rule in override_rules}
        for r in role_rules:
            if r["action"] not in override_actions:
                combined_rules.append(r)  # keep role rule if not overridden
        combined_rules.extend(override_rules)
    else:
        combined_rules = role_rules

    # Evaluate rules (deny > allow)
    matched_allow = None
    for rule in combined_rules:
        if not check_action_pattern_match(rule.get("action", "*"), action):
            continue

        if check_permission_entry_matches(rule.get("_entry"), {"id": uid}, target, req.resource,
                                          rule.get("_selectedIds"), rule.get("_selectedCreators"),
                                          effect=rule["effect"], action=action):
            if rule["effect"].lower() == "deny":
                return {"decision": "DENY", "matched": rule, "source": "override+role"}
            if rule["effect"].lower() == "allow" and not matched_allow:
                matched_allow = rule

    # Allow if matched, otherwise deny
    if matched_allow:
        return {"decision": "ALLOW", "matched": matched_allow, "source": "override+role"}

    return {"decision": "DENY", "reason": "No matching allow", "matched": None, "source": "none"}
