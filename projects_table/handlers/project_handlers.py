# -------------------- PROJECT REQUEST HANDLERS --------------------
import json
import logging
from typing import Dict, Any

# Import services only - handlers should be thin
from services.project_service import ProjectService
from utils.response_helpers import build_response

# Setup logging
logger = logging.getLogger("project_handlers")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def handle_create_project(request_event, request_body, requesting_user_id, requesting_user_role, requesting_user_privileges):
    """Lean handler - delegates to service layer"""
    logger.info(f"Creating project request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectService.handle_create_project_request(
            request_body, 
            requesting_user_id, 
            requesting_user_role, 
            requesting_user_privileges
        )
        
        return build_response(
            event=request_event,
            data=result["data"],
            status=result["status"]
        )
        
    except ValueError as ve:
        return build_response(
            event=request_event,
            error=str(ve),
            status=400
        )
    except PermissionError as pe:
        return build_response(
            event=request_event,
            error=str(pe),
            status=403
        )
    except Exception as e:
        logger.error(f"Create project handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )

def handle_get_projects(request_event, requesting_user_id, requesting_user_role, requesting_user_privileges):
    """Lean handler - delegates to service layer"""
    query_params = request_event.get("queryStringParameters") or {}
    
    logger.info(f"Get projects request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectService.handle_get_projects_request(
            query_params,
            requesting_user_id, 
            requesting_user_role, 
            requesting_user_privileges
        )
        
        return build_response(
            event=request_event,
            data=result["data"],
            status=result["status"]
        )
        
    except ValueError as ve:
        return build_response(
            event=request_event,
            error=str(ve),
            status=400
        )
    except PermissionError as pe:
        return build_response(
            event=request_event,
            error=str(pe),
            status=403
        )
    except Exception as e:
        logger.error(f"Get projects handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )

def handle_permissions_test(event_payload, authenticated_user):
    """Lean handler - delegates to service layer"""
    qs = event_payload.get("queryStringParameters") or {}
    user_id = authenticated_user["user_id"]
    
    try:
        # Delegate to service
        result = ProjectService.handle_permissions_test_request(qs, user_id)
        
        return build_response(
            event=event_payload,
            data=result["data"],
            status=result["status"]
        )
        
    except Exception as e:
        logger.error(f"Permissions test handler error: {e}")
        return build_response(
            event=event_payload,
            error="Internal server error",
            status=500
        )