# Policy engine integration service
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("policy_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class PolicyService:
    """Service for policy engine integration and authorization checks"""
    
    def __init__(self):
        try:
            from policy_engine import (
                can_do, 
                get_allowed_record_ids, 
                can_access_record,
                get_accessible_records_filter,
                get_user_scopes_summary,
                get_user_permissions_debug
            )
            self._can_do = can_do
            self._get_allowed_record_ids = get_allowed_record_ids
            self._can_access_record = can_access_record
            self._get_accessible_records_filter = get_accessible_records_filter
            self._get_user_scopes_summary = get_user_scopes_summary
            self._get_user_permissions_debug = get_user_permissions_debug
            self._available = True
            logger.info("✅ Policy engine integrated successfully")
        except ImportError as e:
            logger.warning(f"❌ Policy engine import failed: {e}")
            self._available = False
            self._setup_fallback_functions()

    def _setup_fallback_functions(self):
        """Setup fallback functions when policy engine is not available"""
        def fallback_can_do(user_id: str, module: str, action: str, **kwargs) -> bool:
            logger.debug(f"🔄 FALLBACK: can_do({user_id}, {module}, {action})")
            return True
        
        def fallback_get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
            logger.debug(f"🔄 FALLBACK: get_allowed_record_ids({user_id}, {module}, {action})")
            return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}
        
        def fallback_can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
            logger.debug(f"🔄 FALLBACK: can_access_record({user_id}, {module}, {action}, {record_id})")
            return True
        
        def fallback_get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
            return {"type": "all", "scopes": ["fallback"], "pattern": "all"}
        
        def fallback_get_user_scopes_summary(user_id: str, module: str) -> Dict[str, Any]:
            return {"user_id": user_id, "module": module, "fallback": True}
        
        def fallback_get_user_permissions_debug(user_id: str, module: str) -> Dict[str, Any]:
            return {"user_id": user_id, "module": module, "fallback": True}

        self._can_do = fallback_can_do
        self._get_allowed_record_ids = fallback_get_allowed_record_ids
        self._can_access_record = fallback_can_access_record
        self._get_accessible_records_filter = fallback_get_accessible_records_filter
        self._get_user_scopes_summary = fallback_get_user_scopes_summary
        self._get_user_permissions_debug = fallback_get_user_permissions_debug

    def is_available(self) -> bool:
        """Check if policy engine is available"""
        return self._available

    def can_do(self, user_id: str, module: str, action: str, **kwargs) -> bool:
        """Check if user can perform an action on a module"""
        return self._can_do(user_id, module, action, **kwargs)

    def get_allowed_record_ids(self, user_id: str, module: str, action: str) -> Dict[str, Any]:
        """Get allowed record IDs for a user action"""
        return self._get_allowed_record_ids(user_id, module, action)

    def can_access_record(self, user_id: str, module: str, action: str, record_id: str) -> bool:
        """Check if user can access a specific record"""
        return self._can_access_record(user_id, module, action, record_id)

    def get_accessible_records_filter(self, user_id: str, module: str, action: str) -> Dict[str, Any]:
        """Get filter criteria for accessible records"""
        return self._get_accessible_records_filter(user_id, module, action)

    def get_user_scopes_summary(self, user_id: str, module: str) -> Dict[str, Any]:
        """Get user scopes summary for debugging"""
        return self._get_user_scopes_summary(user_id, module)

    def get_user_permissions_debug(self, user_id: str, module: str) -> Dict[str, Any]:
        """Get detailed permissions debug information"""
        return self._get_user_permissions_debug(user_id, module)

    def get_approval_permissions_summary(self, user_id: str, approval_id: str = None) -> Dict[str, Any]:
        """Get comprehensive summary of approval permissions for debugging"""
        if not self._available:
            return {"error": "Policy engine not available"}
        
        try:
            summary = self._get_user_scopes_summary(user_id, "Approvals")
            
            # Add pattern and statistics information
            for action in ["view", "raise", "approve_reject", "email"]:
                scope_result = self._get_allowed_record_ids(user_id, "Approvals", action)
                access_filter = self._get_accessible_records_filter(user_id, "Approvals", action)
                
                if action in summary.get("actions", {}):
                    summary["actions"][action].update({
                        "pattern": access_filter.get("pattern", "unknown"),
                        "filterType": access_filter.get("type", "none"),
                        "stats": scope_result.get("stats", {}),
                        "hasAllAccess": scope_result.get("all", False),
                        "deniedCount": len(scope_result.get("denied_ids", []))
                    })
            
            if approval_id:
                # Add specific approval permissions
                summary["specificApproval"] = {
                    "approvalID": approval_id,
                    "canView": self._can_access_record(user_id, "Approvals", "view", approval_id),
                    "canApproveReject": self._can_access_record(user_id, "Approvals", "approve_reject", approval_id),
                    "canRaise": self._can_do(user_id, "Approvals", "raise"),
                    "canEmail": self._can_do(user_id, "Approvals", "email")
                }
            
            return summary
        except Exception as e:
            logger.error(f"Error getting permissions summary: {e}")
            return {"error": str(e)}

logger.info("✅ Policy service initialized")