# -------------------- POLICY ENGINE SERVICE --------------------
import logging
from typing import Dict, Any, List, Optional

# Setup logger
logger = logging.getLogger(__name__)

class PolicyService:
    """Service for policy engine integration"""
    
    def __init__(self):
        self.policy_engine_available = self._check_policy_engine()
    
    def _check_policy_engine(self) -> bool:
        """Check if policy engine is available"""
        try:
            # Try to import policy engine components
            from policy_engine import (
                can_do, 
                get_allowed_record_ids, 
                can_access_record,
                evaluate,
                AccessRequest,
                get_accessible_records_filter,
                get_user_scopes_summary,
                get_user_permissions_debug,
                _get_records_by_creators
            )
            logger.info("✅ Policy engine imported successfully")
            return True
        except ImportError as e:
            logger.warning(f"❌ Policy engine import failed: {e}")
            return False
    
    def can_do(self, user_id: str, module: str, action: str, **kwargs) -> bool:
        """Check if user can perform action on module"""
        if not self.policy_engine_available:
            logger.debug(f"🔄 FALLBACK: can_do({user_id}, {module}, {action})")
            return True
        
        try:
            from policy_engine import can_do
            return can_do(user_id, module, action, **kwargs)
        except Exception as e:
            logger.error(f"Error in policy engine can_do: {e}")
            return False
    
    def get_allowed_record_ids(self, user_id: str, module: str, action: str) -> Dict[str, Any]:
        """Get allowed record IDs for user action"""
        if not self.policy_engine_available:
            logger.debug(f"🔄 FALLBACK: get_allowed_record_ids({user_id}, {module}, {action})")
            return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}
        
        try:
            from policy_engine import get_allowed_record_ids
            return get_allowed_record_ids(user_id, module, action)
        except Exception as e:
            logger.error(f"Error in policy engine get_allowed_record_ids: {e}")
            return {"all": False, "ids": set(), "scopes": [], "pattern": "error"}
    
    def can_access_record(self, user_id: str, module: str, action: str, record_id: str) -> bool:
        """Check if user can access specific record"""
        if not self.policy_engine_available:
            logger.debug(f"🔄 FALLBACK: can_access_record({user_id}, {module}, {action}, {record_id})")
            return True
        
        try:
            from policy_engine import can_access_record
            return can_access_record(user_id, module, action, record_id)
        except Exception as e:
            logger.error(f"Error in policy engine can_access_record: {e}")
            return False
    
    def get_accessible_records_filter(self, user_id: str, module: str, action: str) -> Dict[str, Any]:
        """Get filter criteria for accessing records"""
        if not self.policy_engine_available:
            return {"type": "all", "scopes": ["fallback"], "pattern": "all"}
        
        try:
            from policy_engine import get_accessible_records_filter
            return get_accessible_records_filter(user_id, module, action)
        except Exception as e:
            logger.error(f"Error in policy engine get_accessible_records_filter: {e}")
            return {"type": "none", "scopes": [], "pattern": "error"}
    
    def get_user_scopes_summary(self, user_id: str, module: str) -> Dict[str, Any]:
        """Get user scope summary"""
        if not self.policy_engine_available:
            return {"user_id": user_id, "module": module, "fallback": True}
        
        try:
            from policy_engine import get_user_scopes_summary
            return get_user_scopes_summary(user_id, module)
        except Exception as e:
            logger.error(f"Error in policy engine get_user_scopes_summary: {e}")
            return {"user_id": user_id, "module": module, "error": str(e)}
    
    def get_user_permissions_debug(self, user_id: str, module: str) -> Dict[str, Any]:
        """Get debug permissions info"""
        if not self.policy_engine_available:
            return {"user_id": user_id, "module": module, "fallback": True}
        
        try:
            from policy_engine import get_user_permissions_debug
            return get_user_permissions_debug(user_id, module)
        except Exception as e:
            logger.error(f"Error in policy engine get_user_permissions_debug: {e}")
            return {"user_id": user_id, "module": module, "error": str(e)}

# Create global instance
policy_service = PolicyService()