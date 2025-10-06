from typing import Any, Dict

# ========== COMPREHENSIVE POLICY ENGINE INTEGRATION ==========
try:
    from policy_engine import (
        can_do, 
        get_allowed_record_ids, 
        can_access_record,
        get_accessible_records_filter,
        get_user_scopes_summary,
        get_user_permissions_debug
    )
    POLICY_ENGINE_AVAILABLE = True
    print("✅ Comprehensive policy engine imported successfully for Roles")
except Exception as e:
    print(f"❌ Comprehensive policy engine import failed: {e}")
    POLICY_ENGINE_AVAILABLE = False

    # Safe fallbacks (dev only)
    def can_do(user_id: str, module: str, action: str, **kwargs) -> bool:
        print(f"🔄 FALLBACK: can_do({user_id}, {module}, {action})")
        return True

    def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
        print(f"🔄 FALLBACK: get_allowed_record_ids({user_id}, {module}, {action})")
        return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}

    def can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
        print(f"🔄 FALLBACK: can_access_record({user_id}, {module}, {action}, {record_id})")
        return True

    def get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"type": "all", "scopes": ["fallback"], "pattern": "all"}

    def get_user_scopes_summary(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}

    def get_user_permissions_debug(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}
