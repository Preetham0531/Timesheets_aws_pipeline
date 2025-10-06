"""
Policy Service
Handles all policy engine integrations and authorization logic.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from utils import build_response

logger = logging.getLogger("policy_service")

# Policy engine integration
try:
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
    POLICY_ENGINE_AVAILABLE = True
    logger.info("✅ Policy engine imported successfully")
except ImportError as e:
    logger.warning(f"❌ Policy engine import failed: {e}")
    POLICY_ENGINE_AVAILABLE = False
    
    # Fallback functions for development
    def can_do(user_id: str, module: str, action: str, **kwargs) -> bool:
        logger.info(f"🔄 FALLBACK: can_do({user_id}, {module}, {action})")
        return True
    
    def get_allowed_record_ids(user_id: str, module: str, action: str) -> Dict[str, Any]:
        logger.info(f"🔄 FALLBACK: get_allowed_record_ids({user_id}, {module}, {action})")
        return {"all": True, "ids": None, "scopes": ["fallback"], "pattern": "all"}
    
    def can_access_record(user_id: str, module: str, action: str, record_id: str) -> bool:
        logger.info(f"🔄 FALLBACK: can_access_record({user_id}, {module}, {action}, {record_id})")
        return True
    
    def get_accessible_records_filter(user_id: str, module: str, action: str) -> Dict[str, Any]:
        return {"type": "all", "scopes": ["fallback"], "pattern": "all"}
    
    def get_user_scopes_summary(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}
    
    def get_user_permissions_debug(user_id: str, module: str) -> Dict[str, Any]:
        return {"user_id": user_id, "module": module, "fallback": True}
    
    def _get_records_by_creators(creator_user_ids: List[str], module: str) -> set:
        return set()

class PolicyService:
    """Service for handling policy engine operations and authorization"""
    
    def __init__(self):
        self.policy_available = POLICY_ENGINE_AVAILABLE

    def can_create_client(self, user_id: str) -> bool:
        """Check if user can create clients"""
        return can_do(user_id, "Clients", "create")

    def can_view_client(self, user_id: str, client_id: str = None) -> bool:
        """Check if user can view client(s)"""
        if client_id:
            return can_access_record(user_id, "Clients", "view", client_id)
        return can_do(user_id, "Clients", "view")

    def can_modify_client(self, user_id: str, client_id: str) -> bool:
        """Check if user can modify a specific client"""
        return can_access_record(user_id, "Clients", "modify", client_id)

    def can_delete_client(self, user_id: str, client_id: str) -> bool:
        """Check if user can delete a specific client"""
        return can_access_record(user_id, "Clients", "delete", client_id)

    def can_view_projects(self, user_id: str) -> bool:
        """Check if user can view projects"""
        return can_do(user_id, "Projects", "view")

    def get_accessible_records_filter(self, user_id: str, action: str) -> Dict[str, Any]:
        """Get filter criteria for accessible clients"""
        return get_accessible_records_filter(user_id, "Clients", action)

    def get_debug_info(self, user_id: str, event_payload: Dict[str, Any], 
                      include_projects: bool = False) -> Dict[str, Any]:
        """Get debug information for permissions"""
        if not POLICY_ENGINE_AVAILABLE:
            return build_response(
                event=event_payload,
                data={"error": "Policy engine not available"},
                status=503
            )
        
        try:
            debug_info = get_user_permissions_debug(user_id, "Clients")
            if include_projects:
                debug_info["Projects"] = get_user_permissions_debug(user_id, "Projects")
            
            # Add creator-based access info
            access_filter = get_accessible_records_filter(user_id, "Clients", "view")
            debug_info["creatorBasedAccess"] = {
                "hasCreatorAccess": "selected_by_creator" in access_filter.get("scopes", []),
                "filterType": access_filter.get("type", "none"),
                "creatorIds": access_filter.get("creator_ids", [])[:5],
                "creatorCount": len(access_filter.get("creator_ids", [])),
                "supportsCreatorBased": True
            }
            
            return build_response(
                event=event_payload,
                data={"debugInfo": debug_info},
                status=200
            )
        except Exception as e:
            logger.error(f"Debug summary failed: {e}")
            return build_response(
                event=event_payload,
                data={"error": f"Debug failed: {e}"},
                status=500
            )

    def build_authorization_error(self, event_payload: Dict[str, Any], action: str, user_id: str,
                                client_id: str = None, existing_client: Dict[str, Any] = None) -> Dict[str, Any]:
        """Build detailed authorization error response"""
        if not POLICY_ENGINE_AVAILABLE:
            return build_response(
                event=event_payload,
                status=403,
                data={"error": f"Not authorized to {action} client", "clientID": client_id}
            )
        
        try:
            scope_result = get_allowed_record_ids(user_id, "Clients", action)
            access_filter = get_accessible_records_filter(user_id, "Clients", action)
            
            error_data = {
                "error": f"Not authorized to {action} client",
                "pattern": access_filter.get("pattern", "unknown"),
                "scopes": scope_result.get("scopes", [])
            }
            
            if client_id:
                error_data["clientID"] = client_id
            
            if existing_client:
                error_data["clientCreatedBy"] = existing_client.get("createdBy")
                error_data["isOwnClient"] = existing_client.get("createdBy") == user_id
            
            # Add creator-based access hints
            if "selected_by_creator" in scope_result.get("scopes", []):
                error_data["hint"] = f"You have creator-based access - you can only {action} clients created by specific users"
                error_data["hasCreatorAccess"] = True
            
            # Add pattern-specific information
            if scope_result.get("all", False):
                denied_count = len(scope_result.get("denied_ids", []))
                error_data["hint"] = f"You have {action} access to all clients except {denied_count} denied ones"
            else:
                allowed_count = len(scope_result.get("ids", []))
                error_data["allowedCount"] = allowed_count
                error_data["hint"] = f"You can only {action} {allowed_count} specific clients"
            
            return build_response(event=event_payload, status=403, data=error_data)
            
        except Exception as e:
            logger.error(f"Error building authorization error: {e}")
            return build_response(
                event=event_payload,
                status=403,
                data={"error": f"Not authorized to {action} client", "clientID": client_id}
            )

    def build_delete_authorization_error(self, event_payload: Dict[str, Any], 
                                       denied: List[str], user_id: str) -> Dict[str, Any]:
        """Build authorization error for delete operations"""
        if not POLICY_ENGINE_AVAILABLE:
            return build_response(
                event=event_payload,
                status=403,
                data={"error": "Not authorized to delete some clients", "denied": denied}
            )
        
        try:
            scope_result = get_allowed_record_ids(user_id, "Clients", "delete")
            access_filter = get_accessible_records_filter(user_id, "Clients", "delete")
            
            error_data = {
                "error": "Not authorized to delete some clients",
                "denied": denied,
                "pattern": access_filter.get("pattern", "unknown"),
                "scopes": scope_result.get("scopes", [])
            }
            
            # Add pattern-specific information
            if scope_result.get("all", False):
                denied_count = len(scope_result.get("denied_ids", []))
                error_data["hint"] = f"You have delete access to all clients except {denied_count} denied ones"
            else:
                allowed_count = len(scope_result.get("ids", []))
                error_data["allowedCount"] = allowed_count
                error_data["hint"] = f"You can only delete {allowed_count} specific clients"
            
            return build_response(event=event_payload, status=403, data=error_data)
            
        except Exception as e:
            logger.error(f"Error building delete authorization error: {e}")
            return build_response(
                event=event_payload,
                status=403,
                data={"error": "Not authorized to delete some clients", "denied": denied}
            )

    def build_list_response(self, event_payload: Dict[str, Any], formatted_items: List[Dict[str, Any]],
                           access_filter: Dict[str, Any], view_type: str) -> Dict[str, Any]:
        """Build response for client list operations"""
        filter_type = access_filter.get("type", "none")
        active_scopes = access_filter.get("scopes", [])
        pattern = access_filter.get("pattern", "unknown")
        
        response_data = {
            "clients": formatted_items,
            "totalCount": len(formatted_items),
            "scope": "+".join(active_scopes) if active_scopes else filter_type,
            "activeScopes": active_scopes,
            "policyEngineAvailable": POLICY_ENGINE_AVAILABLE,
            "filterType": filter_type,
            "pattern": pattern,
            "viewType": view_type
        }
        
        # Add statistics for debugging
        if "stats" in access_filter:
            response_data["policyStats"] = access_filter["stats"]
        
        # Add creator-based debug info
        if filter_type in ["creator_based", "mixed"]:
            response_data["creatorInfo"] = {
                "creatorCount": len(access_filter.get("creator_ids", [])),
                "creatorIds": access_filter.get("creator_ids", [])[:3],
                "hasCreatorAccess": len(access_filter.get("creator_ids", [])) > 0
            }
        
        return build_response(
            event=event_payload,
            data=response_data,
            status=200,
        )

    def test_permissions(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Test permissions endpoint for debugging"""
        qs = event_payload.get("queryStringParameters") or {}
        user_id = authenticated_user["user_id"]
        
        test_user_id = qs.get("testUserId", user_id)
        client_id = qs.get("clientID")
        action = qs.get("action", "view")
        
        if not POLICY_ENGINE_AVAILABLE:
            return build_response(
                event=event_payload,
                data={"error": "Policy engine not available"},
                status=503
            )
        
        try:
            if client_id:
                test_results = self._test_client_permissions(test_user_id, client_id)
            else:
                test_results = self._get_client_permissions_summary(test_user_id)
            
            return build_response(
                event=event_payload,
                data={
                    "testResults": test_results,
                    "currentUser": user_id,
                    "testUser": test_user_id
                },
                status=200
            )
            
        except Exception as e:
            logger.error(f"Permissions test failed: {e}")
            return build_response(
                event=event_payload,
                data={"error": f"Test failed: {e}"},
                status=500
            )

    def _get_client_permissions_summary(self, user_id: str, client_id: str = None) -> Dict[str, Any]:
        """Get comprehensive summary of client permissions for debugging"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Policy engine not available"}
        
        try:
            summary = get_user_scopes_summary(user_id, "Clients")
            
            # Add pattern and statistics information
            for action in ["view", "create", "modify", "delete"]:
                scope_result = get_allowed_record_ids(user_id, "Clients", action)
                access_filter = get_accessible_records_filter(user_id, "Clients", action)
                
                if action in summary.get("actions", {}):
                    summary["actions"][action].update({
                        "pattern": access_filter.get("pattern", "unknown"),
                        "filterType": access_filter.get("type", "none"),
                        "stats": scope_result.get("stats", {}),
                        "hasAllAccess": scope_result.get("all", False),
                        "deniedCount": len(scope_result.get("denied_ids", []))
                    })
            
            if client_id:
                summary["specificClient"] = {
                    "clientID": client_id,
                    "canView": can_access_record(user_id, "Clients", "view", client_id),
                    "canModify": can_access_record(user_id, "Clients", "modify", client_id),
                    "canDelete": can_access_record(user_id, "Clients", "delete", client_id)
                }
            
            return summary
        except Exception as e:
            logger.error(f"Error getting permissions summary: {e}")
            return {"error": str(e)}

    def _test_client_permissions(self, user_id: str, client_id: str) -> Dict[str, Any]:
        """Test all permission patterns for a specific client"""
        if not POLICY_ENGINE_AVAILABLE:
            return {"error": "Policy engine not available"}
        
        try:
            test_results = {
                "user_id": user_id,
                "client_id": client_id,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "permissions": {},
                "scopes": {}
            }
            
            # Test each action
            for action in ["view", "create", "modify", "delete"]:
                can_access = can_access_record(user_id, "Clients", action, client_id)
                scope_result = get_allowed_record_ids(user_id, "Clients", action)
                access_filter = get_accessible_records_filter(user_id, "Clients", action)
                
                test_results["permissions"][action] = {
                    "canAccess": can_access,
                    "pattern": access_filter.get("pattern", "unknown"),
                    "hasAllAccess": scope_result.get("all", False),
                    "inAllowedIds": client_id in scope_result.get("ids", set()),
                    "inDeniedIds": client_id in scope_result.get("denied_ids", set())
                }
                
                test_results["scopes"][action] = {
                    "scopes": scope_result.get("scopes", []),
                    "allowedCount": len(scope_result.get("ids", set())) if not scope_result.get("all", False) else "unlimited",
                    "deniedCount": len(scope_result.get("denied_ids", set())),
                    "stats": scope_result.get("stats", {})
                }
            
            return test_results
            
        except Exception as e:
            logger.error(f"Error testing client permissions: {e}")
            return {"error": str(e)}