import json
from typing import Any, Dict

def _clean_selective_access_data(dst: dict, action: str, permission_value: list) -> None:
    """
    Clean up selective access data (SelectedIds, SelectedCreators, etc.) when permissions change
    to values that make them irrelevant.
    
    Args:
        dst: The destination policy dict for a module
        action: The action being updated (e.g., 'view', 'create')
        permission_value: The new permission value list (e.g., ['all'], ['self'], ['selected_by_creator'])
    """
    # Always clean up SelectedCreators if permission doesn't include selected_by_creator
    if "selected_by_creator" not in permission_value:
        if "SelectedCreators" in dst and action in dst["SelectedCreators"]:
            del dst["SelectedCreators"][action]
            # Remove empty SelectedCreators dict
            if not dst["SelectedCreators"]:
                del dst["SelectedCreators"]
    
    # Always clean up SelectedIds if permission doesn't include selected_ids
    if "selected_ids" not in permission_value:
        if "SelectedIds" in dst and action in dst["SelectedIds"]:
            del dst["SelectedIds"][action]
            # Remove empty SelectedIds dict
            if not dst["SelectedIds"]:
                del dst["SelectedIds"]
    
    # Final cleanup: remove empty SelectedIds/SelectedCreators dicts
    if "SelectedIds" in dst and not dst["SelectedIds"]:
        del dst["SelectedIds"]
    if "SelectedCreators" in dst and not dst["SelectedCreators"]:
        del dst["SelectedCreators"]

def normalize_policies_compat(mods: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for module, block in (mods or {}).items():
        if not isinstance(block, dict):
            continue
        nb = {}
        # allow
        if "allow" in block and isinstance(block["allow"], dict):
            na = {}
            for action, permission in block["allow"].items():
                if isinstance(permission, list):
                    na[action] = permission
                elif isinstance(permission, bool):
                    na[action] = ["all"] if permission else []
                elif isinstance(permission, str):
                    na[action] = [permission]
                else:
                    na[action] = []
            nb["allow"] = na
        # deny
        if "deny" in block and isinstance(block["deny"], dict):
            nd = {}
            for action, permission in block["deny"].items():
                if isinstance(permission, list):
                    nd[action] = permission
                elif isinstance(permission, str):
                    nd[action] = [permission]
                else:
                    nd[action] = []
            nb["deny"] = nd
        # SelectedIds
        if "SelectedIds" in block and isinstance(block["SelectedIds"], dict):
            ns = {}
            for action, ids in block["SelectedIds"].items():
                if isinstance(ids, dict):
                    ns[action] = {str(k): str(v) for k, v in ids.items()}
                elif isinstance(ids, list):
                    ns[action] = [str(x) for x in ids]
            nb["SelectedIds"] = ns
        # DeniedIds
        if "DeniedIds" in block and isinstance(block["DeniedIds"], dict):
            nd = {}
            for action, ids in block["DeniedIds"].items():
                if isinstance(ids, dict):
                    nd[action] = {str(k): str(v) for k, v in ids.items()}
                elif isinstance(ids, list):
                    nd[action] = [str(x) for x in ids]
            nb["DeniedIds"] = nd
        # SelectedCreators
        if "SelectedCreators" in block and isinstance(block["SelectedCreators"], dict):
            nc = {}
            for action, creators in block["SelectedCreators"].items():
                if isinstance(creators, dict):
                    nc[action] = {str(k): str(v) for k, v in creators.items()}
                elif isinstance(creators, list):
                    nc[action] = [str(x) for x in creators]
            nb["SelectedCreators"] = nc
        # DeniedCreators
        if "DeniedCreators" in block and isinstance(block["DeniedCreators"], dict):
            ndc = {}
            for action, creators in block["DeniedCreators"].items():
                if isinstance(creators, dict):
                    ndc[action] = {str(k): str(v) for k, v in creators.items()}
                elif isinstance(creators, list):
                    ndc[action] = [str(x) for x in creators]
            nb["DeniedCreators"] = ndc
        
        # Apply cleanup logic based on allow permissions
        if "allow" in nb and isinstance(nb["allow"], dict):
            for action, permission_value in nb["allow"].items():
                if isinstance(permission_value, list):
                    _clean_selective_access_data(nb, action, permission_value)
        
        if nb:
            out[module] = nb
    return out

def has_any_allow(policies: Dict[str, Any]) -> bool:
    for blk in (policies or {}).values():
        allow = blk.get("allow")
        if isinstance(allow, dict):
            for v in allow.values():
                if v is True:
                    return True
                if isinstance(v, list) and v:
                    return True
    return False

def deep_merge_policies(current: dict, patch: dict) -> dict:
    if not isinstance(current, dict):
        current = {}
    if not isinstance(patch, dict):
        return current
    out = json.loads(json.dumps(current))
    for mod, pblock in patch.items():
        if not isinstance(pblock, dict):
            continue
        dst = out.setdefault(mod, {})
        
        # Handle allow permissions and clean up related selective data when changing permissions
        if "allow" in pblock and isinstance(pblock["allow"], dict):
            a_dst = dst.setdefault("allow", {})
            for act, val in pblock["allow"].items():
                a_dst[act] = val
                
                # Clean up selective access data based on the new permission value
                if isinstance(val, list):
                    _clean_selective_access_data(dst, act, val)
        
        # deny
        if "deny" in pblock and isinstance(pblock["deny"], dict):
            d_dst = dst.setdefault("deny", {})
            for act, val in pblock["deny"].items():
                d_dst[act] = val
        
        # SelectedIds - only process if explicitly provided in the patch
        if "SelectedIds" in pblock and isinstance(pblock["SelectedIds"], dict):
            s_dst = dst.setdefault("SelectedIds", {})
            for act, ids in pblock["SelectedIds"].items():
                if isinstance(ids, dict):
                    d = s_dst.setdefault(act, {})
                    d.update({str(k): (str(v) if v is not None else "") for k, v in ids.items()})
                    s_dst[act] = d
                elif isinstance(ids, list):
                    s_dst[act] = [str(x) for x in ids]
        
        # DeniedIds
        if "DeniedIds" in pblock and isinstance(pblock["DeniedIds"], dict):
            d_dst = dst.setdefault("DeniedIds", {})
            for act, ids in pblock["DeniedIds"].items():
                if isinstance(ids, dict):
                    d = d_dst.setdefault(act, {})
                    d.update({str(k): (str(v) if v is not None else "") for k, v in ids.items()})
                    d_dst[act] = d
                elif isinstance(ids, list):
                    d_dst[act] = [str(x) for x in ids]
        
        # SelectedCreators - only process if explicitly provided in the patch
        if "SelectedCreators" in pblock and isinstance(pblock["SelectedCreators"], dict):
            c_dst = dst.setdefault("SelectedCreators", {})
            for act, creators in pblock["SelectedCreators"].items():
                if isinstance(creators, dict):
                    d = c_dst.setdefault(act, {})
                    d.update({str(k): (str(v) if v is not None else "") for k, v in creators.items()})
                    c_dst[act] = d
                elif isinstance(creators, list):
                    c_dst[act] = [str(x) for x in creators]
        
        # DeniedCreators
        if "DeniedCreators" in pblock and isinstance(pblock["DeniedCreators"], dict):
            dc_dst = dst.setdefault("DeniedCreators", {})
            for act, creators in pblock["DeniedCreators"].items():
                if isinstance(creators, dict):
                    d = dc_dst.setdefault(act, {})
                    d.update({str(k): (str(v) if v is not None else "") for k, v in creators.items()})
                    dc_dst[act] = d
                elif isinstance(creators, list):
                    dc_dst[act] = [str(x) for x in creators]
        
        # Final cleanup: remove any empty selective access dictionaries
        for key in ["SelectedIds", "SelectedCreators", "DeniedIds", "DeniedCreators"]:
            if key in dst and not dst[key]:
                del dst[key]
    
    return out


def deep_replace_policies(current: dict, patch: dict) -> dict:
    """
    Replace (not merge) policies with the patch data. This is used for direct role edits
    where frontend payloads should completely replace existing values instead of appending.
    """
    if not isinstance(current, dict):
        current = {}
    if not isinstance(patch, dict):
        return current
    out = json.loads(json.dumps(current))
    for mod, pblock in patch.items():
        if not isinstance(pblock, dict):
            continue
        dst = out.setdefault(mod, {})
        
        # Handle allow permissions and clean up related selective data when changing permissions
        if "allow" in pblock and isinstance(pblock["allow"], dict):
            a_dst = dst.setdefault("allow", {})
            for act, val in pblock["allow"].items():
                a_dst[act] = val
                
                # Clean up selective access data based on the new permission value
                if isinstance(val, list):
                    _clean_selective_access_data(dst, act, val)
        
        # deny
        if "deny" in pblock and isinstance(pblock["deny"], dict):
            d_dst = dst.setdefault("deny", {})
            for act, val in pblock["deny"].items():
                d_dst[act] = val
        
        # SelectedIds - REPLACE instead of merge
        if "SelectedIds" in pblock and isinstance(pblock["SelectedIds"], dict):
            s_dst = dst.setdefault("SelectedIds", {})
            for act, ids in pblock["SelectedIds"].items():
                if isinstance(ids, dict):
                    # Replace the entire action's data instead of merging
                    s_dst[act] = {str(k): (str(v) if v is not None else "") for k, v in ids.items()}
                elif isinstance(ids, list):
                    s_dst[act] = [str(x) for x in ids]
        
        # DeniedIds - REPLACE instead of merge
        if "DeniedIds" in pblock and isinstance(pblock["DeniedIds"], dict):
            d_dst = dst.setdefault("DeniedIds", {})
            for act, ids in pblock["DeniedIds"].items():
                if isinstance(ids, dict):
                    # Replace the entire action's data instead of merging
                    d_dst[act] = {str(k): (str(v) if v is not None else "") for k, v in ids.items()}
                elif isinstance(ids, list):
                    d_dst[act] = [str(x) for x in ids]
        
        # SelectedCreators - REPLACE instead of merge
        if "SelectedCreators" in pblock and isinstance(pblock["SelectedCreators"], dict):
            c_dst = dst.setdefault("SelectedCreators", {})
            for act, creators in pblock["SelectedCreators"].items():
                if isinstance(creators, dict):
                    # Replace the entire action's data instead of merging
                    c_dst[act] = {str(k): (str(v) if v is not None else "") for k, v in creators.items()}
                elif isinstance(creators, list):
                    c_dst[act] = [str(x) for x in creators]
        
        # DeniedCreators - REPLACE instead of merge
        if "DeniedCreators" in pblock and isinstance(pblock["DeniedCreators"], dict):
            dc_dst = dst.setdefault("DeniedCreators", {})
            for act, creators in pblock["DeniedCreators"].items():
                if isinstance(creators, dict):
                    # Replace the entire action's data instead of merging
                    dc_dst[act] = {str(k): (str(v) if v is not None else "") for k, v in creators.items()}
                elif isinstance(creators, list):
                    dc_dst[act] = [str(x) for x in creators]
        
        # Final cleanup: remove any empty selective access dictionaries
        for key in ["SelectedIds", "SelectedCreators", "DeniedIds", "DeniedCreators"]:
            if key in dst and not dst[key]:
                del dst[key]
    
    return out
