"""
Client Request Handlers
Handles API Gateway requests for client operations and delegates to services.
"""

import json
import logging
from typing import Dict, Any
from utils import build_response, get_cors_headers
from services.client_service import ClientService
from services.policy_service import PolicyService

logger = logging.getLogger("client_handler")

class ClientHandler:
    def __init__(self):
        self.client_service = ClientService()
        self.policy_service = PolicyService()

    def handle_create(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client creation requests"""
        try:
            return self.client_service.create_client(event_payload, authenticated_user)
        except Exception as e:
            logger.error(f"Create handler error: {e}")
            return build_response(
                event=event_payload,
                error="Internal server error",
                status=500
            )

    def handle_get(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client retrieval requests"""
        try:
            return self.client_service.get_clients(event_payload, authenticated_user)
        except Exception as e:
            logger.error(f"Get handler error: {e}")
            return build_response(
                event=event_payload,
                error="Internal server error",
                status=500
            )

    def handle_update(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client update requests"""
        try:
            return self.client_service.update_client(event_payload, authenticated_user)
        except Exception as e:
            logger.error(f"Update handler error: {e}")
            return build_response(
                event=event_payload,
                error="Internal server error",
                status=500
            )

    def handle_delete(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client deletion requests"""
        try:
            return self.client_service.delete_clients(event_payload, authenticated_user)
        except Exception as e:
            logger.error(f"Delete handler error: {e}")
            return build_response(
                event=event_payload,
                error="Internal server error",
                status=500
            )

    def handle_permissions_test(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Handle permissions testing requests"""
        try:
            return self.policy_service.test_permissions(event_payload, authenticated_user)
        except Exception as e:
            logger.error(f"Permissions test handler error: {e}")
            return build_response(
                event=event_payload,
                error="Internal server error",
                status=500
            )

# Create handler instance for module-level functions
_handler = ClientHandler()

# Export functions to maintain compatibility
def handle_create(event_payload, authenticated_user):
    return _handler.handle_create(event_payload, authenticated_user)

def handle_get(event_payload, authenticated_user):
    return _handler.handle_get(event_payload, authenticated_user)

def handle_update(event_payload, authenticated_user):
    return _handler.handle_update(event_payload, authenticated_user)

def handle_delete(event_payload, authenticated_user):
    return _handler.handle_delete(event_payload, authenticated_user)

def handle_permissions_test(event_payload, authenticated_user):
    return _handler.handle_permissions_test(event_payload, authenticated_user)