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
    resource_resolvers[resource_type] = resolver_function


# ——— Helpers ———
def normalize_to_string_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    string_value = str(value).strip()
    if not string_value:
        return []
    return [item.strip() for item in string_value.split(",") if item.strip()]


def check_action_pattern_match(rule_action_pattern: Any, requested_action: str) -> bool:
    if isinstance(rule_action_pattern, list):
        return any(check_action_pattern_match(action, requested_action) for action in rule_action_pattern)
    return fnmatch.fnmatch(requested_action, str(rule_action_pattern))


def parse_as_object(raw_data):
    if isinstance(raw_data, str):
        try:
            return json.loads(raw_data)
        except Exception:
            return {}
    return raw_data or {}


# ——— DynamoDB Loaders ———
def load_user_assignment_records(user_identifier: str) -> List[Dict[str, Any]]:
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
    role_index_name = os.environ.get("ROLE_BY_NAME_INDEX", "role-rid-index")

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

    try:
        resp = role_policies_table.scan(FilterExpression=Attr("role").eq(role_name))
        items = resp.get("Items", []) or []
        if items:
            return items[0]
    except Exception:
        pass

    return None


# ——— Rule Conversion ———
def convert_permissions_dict_to_rules(
    effect: str,
    permissions_dict: dict,
    extras: dict = None,
    parent_prefix: str = ""
) -> List[Dict[str, Any]]:
    rules = []

    for key, value in (permissions_dict or {}).items():
        full_action = f"{parent_prefix}.{key}" if parent_prefix else key

        # ✅ Handle SelectedIds (inside or outside allow/deny)
        if key == "SelectedIds" and isinstance(value, dict):
            for inner_action, ids in value.items():
                normalized_ids = []
                if isinstance(ids, dict):
                    normalized_ids = list(map(str, ids.keys()))
                else:
                    normalized_ids = normalize_to_string_list(ids)

                rules.append({
                    "effect": effect,
                    "action": inner_action,
                    "_entry": ["selected"],
                    "_selectedIds": normalized_ids
                })
            continue

        # Expand nested dicts
        if isinstance(value, dict):
            rules.extend(
                convert_permissions_dict_to_rules(effect, value, parent_prefix=full_action, extras=extras)
            )
            continue

        # Normalize leaf values
        if isinstance(value, str):
            value = ["all"] if value.lower() == "all" else [value]
        elif isinstance(value, list):
            value = [str(v) for v in value]

        rules.append({
            "effect": effect,
            "action": full_action,
            "_entry": value
        })

    return rules


# ——— Role Rule Extractor ———
def extract_role_permission_rules_for_module(role_name: str, target_module: str) -> List[Dict[str, Any]]:
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

    # Wildcard policies (*)
    if isinstance(policies, dict) and "*" in policies:
        wild = parse_as_object(policies["*"])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(wild.get("allow")), {"action_prefix": "*"}))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(wild.get("deny")), {"action_prefix": "*"}))
        # ✅ Also support sibling SelectedIds at wildcard level
        if "SelectedIds" in wild:
            rules.extend(convert_permissions_dict_to_rules("allow", {"SelectedIds": wild["SelectedIds"]}, {"action_prefix": "*"}))

    # Module-specific policies
    if isinstance(policies, dict) and target_module in policies:
        mod = parse_as_object(policies[target_module])
        rules.extend(convert_permissions_dict_to_rules("allow", parse_as_object(mod.get("allow")), {"action_prefix": target_module}))
        rules.extend(convert_permissions_dict_to_rules("deny", parse_as_object(mod.get("deny")), {"action_prefix": target_module}))
        # ✅ Also support sibling SelectedIds at module level
        if "SelectedIds" in mod:
            rules.extend(convert_permissions_dict_to_rules("allow", {"SelectedIds": mod["SelectedIds"]}, {"action_prefix": target_module}))

    return rules


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
    uid = req.user.get("id")
    module = req.resourceType
    action = req.action

    assignments = load_user_assignment_records(str(uid))

    override_rules: List[Dict[str, Any]] = []
    role_names: List[str] = []

    for rec in assignments:
        ovID = str(rec.get("ovID") or rec.get("SK") or "")
        status = rec.get("Status") or rec.get("status") or "active"

        if status != "active":
            continue

        if ovID.startswith("B#OVR#") and rec.get("module") == module:
            allow = rec.get("Allow") or {}
            deny = rec.get("Deny") or {}
            override_rules.extend(convert_permissions_dict_to_rules("allow", allow, {"action_prefix": module}))
            override_rules.extend(convert_permissions_dict_to_rules("deny", deny, {"action_prefix": module}))
        elif ovID.startswith("A#ROLE#"):
            role_names.append(ovID.split("#", 2)[2])

    role_rules: List[Dict[str, Any]] = []
    for role in role_names:
        role_rules.extend(extract_role_permission_rules_for_module(role, module))

    # Merge role + overrides
    if override_rules:
        override_actions = {rule["action"] for rule in override_rules}
        combined_rules = [r for r in role_rules if r["action"] not in override_actions]
        combined_rules.extend(override_rules)
    else:
        combined_rules = role_rules

    matched_allow = None
    for rule in combined_rules:
        if not check_action_pattern_match(rule.get("action", "*"), action):
            continue

        entries = rule.get("_entry") or []

        if isinstance(entries, list) and "none" in entries:
            return {"decision": "DENY", "reason": "explicit none scope", "matched": rule, "source": "override+role"}

        if rule["effect"].lower() == "allow":
            matched_allow = rule

        if rule["effect"].lower() == "deny":
            return {"decision": "DENY", "matched": rule, "source": "override+role"}

    if matched_allow:
        return {"decision": "ALLOW", "matched": matched_allow, "source": "override+role"}

    return {"decision": "DENY", "reason": "No matching allow", "matched": None, "source": "none"}
