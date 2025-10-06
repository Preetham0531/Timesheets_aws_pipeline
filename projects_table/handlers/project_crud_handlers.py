# -------------------- PROJECT UPDATE AND DELETE HANDLERS --------------------
import json
import logging
import traceback
from typing import Dict, Any, List, Tuple
from datetime import datetime

from services.project_service import ProjectService
from services.project_archive_service import ProjectArchiveService
from utils.response_helpers import build_response

# Setup logging
logger = logging.getLogger("project_crud_handlers")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def _err(event_payload, exc: Exception, code: str, status: int = 500):
    """Standardized error handler with logging"""
    logger.error("%s: %s\n%s", code, exc, traceback.format_exc())
    return build_response(event=event_payload, error="Internal server error", status=status)

def handle_update_project(request_event, request_body, requesting_user_id, requesting_user_role):
    """Lean handler - delegates to service layer"""
    logger.info(f"Update project request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectService.handle_update_project_request(
            request_body, 
            requesting_user_id, 
            requesting_user_role
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
        logger.error(f"Update project handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )

def handle_delete_project(request_event, request_body, requesting_user_id, requesting_user_role):
    """Lean handler - delegates to service layer"""
    logger.info(f"Delete project request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectService.handle_delete_project_request(
            request_body, 
            requesting_user_id
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
        logger.error(f"Delete project handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )


def handle_archive_project(request_event, request_body, requesting_user_id, requesting_user_role):
    """Lean handler - delegates to service layer"""
    logger.info(f"Archive project request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectArchiveService.handle_archive_project_request(
            request_body, 
            requesting_user_id, 
            requesting_user_role
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
        logger.error(f"Archive project handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )

def handle_unarchive_project(request_event, request_body, requesting_user_id, requesting_user_role):
    """Lean handler - delegates to service layer"""
    logger.info(f"Unarchive project request by user {requesting_user_id}")
    
    try:
        # Delegate all business logic to service
        result = ProjectArchiveService.handle_unarchive_project_request(
            request_body, 
            requesting_user_id, 
            requesting_user_role
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
        logger.error(f"Unarchive project handler error: {e}")
        return build_response(
            event=request_event,
            error="Internal server error",
            status=500
        )