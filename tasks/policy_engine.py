from __future__ import annotations
import os
import fnmatch
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable
from boto3.dynamodb.conditions import Key, Attr
import boto3


# ——— DynamoDB Table Setup ———
USER_ASSIGNMENTS_TABLE_NAME = os.environ.get("USER_ASSIGNMENTS_TABLE_NAME")
ROLE_POLICIES_TABLE_NAME = os.environ.get("ROLE_POLICIES_TABLE_NAME")
POLICY_DEFINITIONS_TABLE_NAME = os.environ.get("POLICY_DEFINITIONS_TABLE_NAME")

dynamodb_resource = boto3.resource("dynamodb")
user_assignments_table = dynamodb_resource.Table(USER_ASSIGNMENTS_TABLE_NAME)
role_policies_table = dynamodb_resource.Table(ROLE_POLICIES_TABLE_NAME)
policy_definitions_table = dynamodb_resource.Table(POLICY_DEFINITIONS_TABLE_NAME)


# ——— Resolver Registry ———
resource_resolvers: Dict[str, Callable[[str], Dict[str, Any]]] = {}

def register_resource_resolver(resource_type: str, resolver_function: Callable[[str], Dict[str, Any]]) -> None:
    """Register a resolver function for a resource type."""
    resource_resolvers[resource_type] = resolver_function


# ——— Helpers ———

def normalize_to_string_list(value) -> List[str]:
    """Normalize any input into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    string_value = str(value).strip()
    if not string_value:
        return []
    return [item.strip() for item in string_value.split(",") if item.strip()]


def check_action_pattern_match(rule_action_pattern: Any, requested_action: str) -> bool:
    """Check if requested_action matches rule pattern (supports wildcards)."""
    if isinstance(rule_action_pattern, list):
        return any(check_action_pattern_match(action, requested_action) for action in rule_action_pattern)
    return fnmatch.fnmatch(requested_action, str(rule_action_pattern))


def parse_as_object(raw_data):
    """Safely parse JSON string into a dict, or return object as-is."""
    if isinstance(raw_data, str):
        try:
            return json.loads(raw_data)
        except Exception:
            return {}
    return raw_data or {}


# ——— DynamoDB Loaders ———

def load_user_assignment_records(user_identifier: str) -> List[Dict[str, Any]]:
    """Load user grants/overrides from UserGrants table (handles casing)."""
    all_items = []
    for pk in ["userID", "userId"]:
        try:
            resp = user_assignments_table.query(
                KeyConditionExpression=Key(pk).eq(str(user_identifier))
            )
            all_items.extend(resp.get("Items", []) or [])
        except Exception:
            pass
    return all_items


def load_role_record_by_role_name(role_name: str) -> Optional[Dict[str, Any]]:
    """Load role record from roles_t by role name (query index, fallback scan)."""
    role_index_name = os.environ.get("ROLE_BY_NAME_INDEX", "role-rid-index")

    # First try with index
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

    # Fallback to scan
    try:
        resp = role_policies_table.scan(FilterExpression=Attr("role").eq(role_name))
        items = resp.get("Items", []) or []
        if items:
            return items[0]
    except Exception:
        pass

    return None


# ——— Rule Conversion ———

def convert_permissions_dict_to_rules(effect: str, permissions_dict: dict, extras: dict = None) -> List[Dict[str, Any]]:
    """
    Convert allow/deny dicts into normalized rules.

    Supports:
      - all
      - self
      - selected
      - selected_by_creator
    """
    rules = []

    for action, value in (permissions_dict or {}).items():
        rule = {"effect": effect, "action": action}

        selected_record_ids = None
        selected_creator_ids = None

        # Normalize entry into a scope keyword
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

        # Attach SelectedIds
        if selected_record_ids:
            rule["_selectedIds"] = selected_record_ids
        elif extras and "SelectedIds" in extras and action in (extras.get("SelectedIds") or {}):
            ids_dict = extras["SelectedIds"][action]
            rule["_selectedIds"] = (
                list(map(str, ids_dict.keys())) if isinstance(ids_dict, dict)
                else normalize_to_string_list(ids_dict)
            )

        # Attach SelectedCreators
        if selected_creator_ids:
            rule["_selectedCreators"] = selected_creator_ids
        elif extras and "SelectedCreators" in extras and action in (extras.get("SelectedCreators") or {}):
            creators_dict = extras["SelectedCreators"][action]
            rule["_selectedCreators"] = (
                list(map(str, creators_dict.keys())) if isinstance(creators_dict, dict)
                else normalize_to_string_list(creators_dict)
            )

        rules.append(rule)

    return rules


def extract_role_permission_rules_for_module(role_name: str, target_module: str) -> List[Dict[str, Any]]:
    """Extract normalized allow/deny rules for a given role and module."""
    record = load_role_record_by_role_name(role_name)
    if not record or str(record.get("Status", "active")).lower() != "active":
        return []

    # Parse role policies
    policies = record.get("Policies")
    if isinstance(policies, str):
        try:
            policies = json.loads(policies)
        except Exception:
            policies = {}

    rules: List[Dict[str, Any]] = []

    # Wildcard rules (*)
    if isinstance(policies, dict) and "*" in policies:
        wild = parse_as_object(policies["*"])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(wild.get("allow")), wild))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(wild.get("deny")), wild))

    # Module-specific rules
    if isinstance(policies, dict) and target_module in policies:
        mod = parse_as_object(policies[target_module])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(mod.get("allow")), mod))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(mod.get("deny")), mod))

    return rules


# ——— Rule Evaluation ———

def check_permission_entry_matches(
    entry: Any,
    user: Dict[str, Any],
    target: Dict[str, Any],
    resource: Optional[Dict[str, Any]],
    selected_ids: Optional[List[str]] = None,
    selected_creators: Optional[List[str]] = None,
    effect: str = "allow",
    action: str = ""
) -> bool:
    """Check if a scope entry matches the current request."""
    uid = user.get("id")
    record_id = target.get("recordId")

    if entry is True:
        return True
    if not entry:
        return False

    if isinstance(entry, list):
        allowed = False

        for scope in entry:
            if scope == "none":
                return False
            if scope == "all":
                return True

            # Self scope
            if scope == "self" and resource:
                module = target.get("module")
                if module == "Tasks" and resource.get("createdBy") == uid:
                    allowed = True
                elif module == "ProjectAssignments" and resource.get("assignedBy") == uid:
                    allowed = True
                elif (
                    resource.get("createdBy") == uid
                    or resource.get("ownerUserId") == uid
                    or resource.get("assignedTo") == uid
                    or resource.get("assignedBy") == uid
                ):
                    allowed = True

            # Selected scope
            if scope == "selected":
                target_id = uid if action == "create" else record_id
                if target_id and selected_ids:
                    in_selected = str(target_id) in set(map(str, selected_ids))
                    if effect.lower() == "allow" and in_selected:
                        allowed = True
                    if effect.lower() == "deny" and in_selected:
                        return True  # deny wins

            # Selected by creator scope
            if scope == "selected_by_creator" and resource:
                creator_id = resource.get("createdBy")
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
    """
    Evaluate an access request across user overrides and role policies.
    Deny rules always take precedence over allow rules.
    """
    uid = req.user.get("id")
    module = req.resourceType
    action = req.action

    # Ensure target context has module
    target = req.targetCtx or {"module": module}
    target.setdefault("module", module)

    # Load all user assignments
    assignments = load_user_assignment_records(str(uid))

    override_rules: List[Dict[str, Any]] = []
    role_names: List[str] = []

    # Collect override and role rules
    for rec in assignments:
        ovID = str(rec.get("ovID") or rec.get("SK") or "")
        status = rec.get("Status") or rec.get("status") or "active"

        if status != "active":
            continue

        # Overrides (module-specific)
        if ovID.startswith("B#OVR#") and rec.get("module") == module:
            allow = rec.get("Allow") or {}
            deny = rec.get("Deny") or {}
            override_rules.extend(convert_permissions_dict_to_rules("allow", allow, rec))
            override_rules.extend(convert_permissions_dict_to_rules("deny", deny, rec))

        # Role assignment
        elif ovID.startswith("A#ROLE#"):
            role_names.append(ovID.split("#", 2)[2])

    # Load role rules
    role_rules: List[Dict[str, Any]] = []
    for role in role_names:
        role_rules.extend(extract_role_permission_rules_for_module(role, module))

    # Merge rules (overrides replace only same actions)
    combined_rules: List[Dict[str, Any]] = []
    if override_rules:
        override_actions = {rule["action"] for rule in override_rules}
        for r in role_rules:
            if r["action"] not in override_actions:
                combined_rules.append(r)
        combined_rules.extend(override_rules)
    else:
        combined_rules = role_rules

    # Evaluate rules (deny > allow)
    matched_allow = None
    for rule in combined_rules:
        if not check_action_pattern_match(rule.get("action", "*"), action):
            continue

        if check_permission_entry_matches(
            rule.get("_entry"),
            {"id": uid},
            target,
            req.resource,
            rule.get("_selectedIds"),
            rule.get("_selectedCreators"),
            effect=rule["effect"],
            action=action
        ):
            # Deny wins immediately
            if rule["effect"].lower() == "deny":
                return {"decision": "DENY", "matched": rule, "source": "override+role"}

            # Store allow if first match
            if rule["effect"].lower() == "allow" and not matched_allow:
                matched_allow = rule

    # Final decision
    if matched_allow:
        return {"decision": "ALLOW", "matched": matched_allow, "source": "override+role"}

    # Fail-closed default
    return {"decision": "DENY", "reason": "No matching allow", "matched": None, "source": "none"}
