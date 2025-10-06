import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# ========== POLICY ENGINE INTEGRATION ==========
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
except ImportError as e:
    POLICY_ENGINE_AVAILABLE = False
    
    # Fallback functions for development
    def can_do(user_id: str, module: str, action: str, **kwargs) -> bool:
        return True
    
    def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}
    
    def can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
        return True
    
    def get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"type": "all", "scopes": ["fallback"], "pattern": "all"}
    
    def get_user_scopes_summary(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}
    
    def get_user_permissions_debug(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}

from models.contact_model import ContactModel

# ========= LOGGING =========
logger = logging.getLogger("authorization_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class AuthorizationService:
    """
    Service for handling authorization checks and policy engine integration.
    Provides clean interface for permission validation.
    """
    
    def __init__(self):
        self.contact_model = ContactModel()

    def can_create_contact(self, user_id: str) -> bool:
        """Check if user can create contacts"""
        return can_do(user_id, "Contacts", "create")

    def can_view_contact(self, user_id: str, contact_id: str) -> bool:
        """Check if user can view a specific contact"""
        return can_access_record(user_id, "Contacts", "view", contact_id)

    def can_modify_contact(self, user_id: str, contact_id: str) -> bool:
        """Check if user can modify a specific contact"""
        return can_access_record(user_id, "Contacts", "modify", contact_id)

    def can_delete_contact(self, user_id: str, contact_id: str) -> bool:
        """Check if user can delete a specific contact"""
        return can_access_record(user_id, "Contacts", "delete", contact_id)

    def can_access_client(self, user_id: str, client_id: str) -> bool:
        """Check if user can access a specific client"""
        if not POLICY_ENGINE_AVAILABLE:
            return True
        return can_access_record(user_id, "Clients", "view", client_id)

    def can_view_users(self, user_id: str) -> bool:
        """Check if user can view users list"""
        return can_do(user_id, "Users", "view")

    def get_access_filter(self, user_id: str, module: str, action: str) -> Dict[str, Any]:
        """Get access filter for database queries"""
        return get_accessible_records_filter(user_id, module, action)

    def validate_batch_delete(self, user_id: str, contact_ids: List[str]) -> Dict[str, Any]:
        """
        Validate batch delete authorization
        Returns dict with missing, denied, and valid_contacts lists
        """
        missing = []
        denied = []
        valid_contacts = []
        
        for contact_id in contact_ids:
            try:
                # Check if contact exists
                contact = self.contact_model.get_contact_by_id(contact_id)
                if not contact:
                    missing.append(contact_id)
                    continue
                
                # Check delete permission
                if self.can_delete_contact(user_id, contact_id):
                    valid_contacts.append(contact)
                else:
                    denied.append(contact_id)
                    
            except Exception as e:
                logger.error(f"Error validating contact {contact_id}: {e}")
                denied.append(contact_id)
        
        return {
            "missing": missing,
            "denied": denied,
            "valid_contacts": valid_contacts
        }

    def get_auth_error_details(self, user_id: str, action: str, contact_id: str = None) -> Dict[str, Any]:
        """Get detailed authorization error information"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": f"Not authorized to {action} contact"}
        
        try:
            scope_result = get_allowed_record_ids(user_id, "Contacts", action)
            access_filter = get_accessible_records_filter(user_id, "Contacts", action)
            
            error_data = {
                "error": f"Not authorized to {action} contact",
                "pattern": access_filter.get("pattern", "unknown"),
                "scopes": scope_result.get("scopes", [])
            }
            
            if contact_id:
                error_data["contactID"] = contact_id
                
                # Get contact details for error context
                try:
                    contact = self.contact_model.get_contact_by_id(contact_id)
                    if contact:
                        error_data["contactCreatedBy"] = contact.get("createdBy")
                        error_data["isOwnContact"] = contact.get("createdBy") == user_id
                except Exception:
                    pass
            
            # Add pattern-specific hints
            if "selected_by_creator" in scope_result.get("scopes", []):
                error_data["hint"] = f"You have creator-based {action} access - check if you can {action} contacts created by specific users"
                error_data["hasCreatorAccess"] = True
            
            if scope_result.get("all", False):
                denied_count = len(scope_result.get("denied_ids", []))
                error_data["hint"] = f"You have {action} access to all contacts except {denied_count} denied ones"
            else:
                allowed_count = len(scope_result.get("ids", []))
                error_data["allowedCount"] = allowed_count
                error_data["hint"] = f"You can only {action} {allowed_count} specific contacts"
            
            return error_data
            
        except Exception as e:
            logger.error(f"Error building auth error details: {e}")
            return {"error": f"Not authorized to {action} contact"}

    def get_delete_auth_error_details(self, user_id: str, denied_contact_ids: List[str]) -> Dict[str, Any]:
        """Get detailed error information for batch delete failures"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Not authorized to delete some contacts", "denied": denied_contact_ids}
        
        try:
            # Get user's delete permissions
            scope_result = get_allowed_record_ids(user_id, "Contacts", "delete")
            access_filter = get_accessible_records_filter(user_id, "Contacts", "delete")
            
            error_data = {
                "error": "Not authorized to delete some contacts",
                "denied": denied_contact_ids,
                "pattern": access_filter.get("pattern", "unknown"),
                "scopes": scope_result.get("scopes", [])
            }
            
            # Add pattern-specific hints
            if "selected_by_creator" in scope_result.get("scopes", []):
                error_data["hint"] = "You have creator-based delete access - you can only delete contacts created by specific users"
                error_data["hasCreatorAccess"] = True
            
            if scope_result.get("all", False):
                denied_count = len(scope_result.get("denied_ids", []))
                error_data["hint"] = f"You have delete access to all contacts except {denied_count} denied ones"
            else:
                allowed_count = len(scope_result.get("ids", []))
                error_data["allowedCount"] = allowed_count
                error_data["hint"] = f"You can only delete {allowed_count} specific contacts"
            
            return error_data
            
        except Exception as e:
            logger.error(f"Error building delete auth error details: {e}")
            return {"error": "Not authorized to delete some contacts", "denied": denied_contact_ids}

    def get_permissions_summary(self, user_id: str, contact_id: str = None) -> Dict[str, Any]:
        """Get comprehensive permissions summary"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Policy engine not available"}
        
        try:
            summary = get_user_scopes_summary(user_id, "Contacts")
            
            # Add enhanced pattern information
            for action in ["view", "create", "modify", "delete"]:
                scope_result = get_allowed_record_ids(user_id, "Contacts", action)
                access_filter = get_accessible_records_filter(user_id, "Contacts", action)
                
                if action in summary.get("actions", {}):
                    summary["actions"][action].update({
                        "pattern": access_filter.get("pattern", "unknown"),
                        "filterType": access_filter.get("type", "none"),
                        "stats": scope_result.get("stats", {}),
                        "hasAllAccess": scope_result.get("all", False),
                        "deniedCount": len(scope_result.get("denied_ids", [])),
                        "hasCreatorAccess": "selected_by_creator" in scope_result.get("scopes", []),
                        "creatorCount": len(access_filter.get("creator_ids", []))
                    })
            
            if contact_id:
                # Add specific contact permissions
                summary["specificContact"] = {
                    "contactID": contact_id,
                    "canView": self.can_view_contact(user_id, contact_id),
                    "canModify": self.can_modify_contact(user_id, contact_id),
                    "canDelete": self.can_delete_contact(user_id, contact_id)
                }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting permissions summary: {e}")
            return {"error": str(e)}

    def test_contact_permissions(self, user_id: str, contact_id: str) -> Dict[str, Any]:
        """Test all permission patterns for a specific contact"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Policy engine not available"}
        
        try:
            test_results = {
                "user_id": user_id,
                "contact_id": contact_id,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "permissions": {},
                "scopes": {}
            }
            
            # Test each action
            for action in ["view", "create", "modify", "delete"]:
                # Individual record access
                can_access = can_access_record(user_id, "Contacts", action, contact_id)
                
                # Scope information
                scope_result = get_allowed_record_ids(user_id, "Contacts", action)
                access_filter = get_accessible_records_filter(user_id, "Contacts", action)
                
                test_results["permissions"][action] = {
                    "canAccess": can_access,
                    "pattern": access_filter.get("pattern", "unknown"),
                    "hasAllAccess": scope_result.get("all", False),
                    "inAllowedIds": contact_id in scope_result.get("ids", set()),
                    "inDeniedIds": contact_id in scope_result.get("denied_ids", set()),
                    "hasCreatorAccess": "selected_by_creator" in scope_result.get("scopes", []),
                    "creatorCount": len(access_filter.get("creator_ids", []))
                }
                
                test_results["scopes"][action] = {
                    "scopes": scope_result.get("scopes", []),
                    "allowedCount": len(scope_result.get("ids", set())) if not scope_result.get("all", False) else "unlimited",
                    "deniedCount": len(scope_result.get("denied_ids", set())),
                    "stats": scope_result.get("stats", {}),
                    "creatorIds": access_filter.get("creator_ids", [])[:3]  # First 3 for privacy
                }
            
            return test_results
            
        except Exception as e:
            logger.error(f"Error testing contact permissions: {e}")
            return {"error": str(e)}

    def get_permissions_debug(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive permissions debug information"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Policy engine not available"}
        
        try:
            debug_info = get_user_permissions_debug(user_id, "Contacts")
            
            # Add creator-based access info
            access_filter = get_accessible_records_filter(user_id, "Contacts", "view")
            debug_info["creatorBasedAccess"] = {
                "hasCreatorAccess": "selected_by_creator" in access_filter.get("scopes", []),
                "filterType": access_filter.get("type", "none"),
                "creatorIds": access_filter.get("creator_ids", [])[:5],  # First 5 for privacy
                "creatorCount": len(access_filter.get("creator_ids", [])),
                "supportsCreatorBased": True
            }
            
            return debug_info
            
        except Exception as e:
            logger.error(f"Debug permissions failed: {e}")
            return {"error": f"Debug failed: {e}"}

    def is_policy_engine_available(self) -> bool:
        """Check if policy engine is available"""
        return POLICY_ENGINE_AVAILABLE

logger.info(f"✅ AuthorizationService initialized (Policy Engine: {'Available' if POLICY_ENGINE_AVAILABLE else 'Unavailable'})")