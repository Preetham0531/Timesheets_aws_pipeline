import json
import logging
import traceback
from typing import Dict, Any

# Import handlers - request processing and validation
from handlers.project_handlers import (
    handle_create_project,
    handle_get_projects,
    handle_permissions_test
)
from handlers.project_crud_handlers import (
    handle_update_project,
    handle_delete_project,
    handle_archive_project,
    handle_unarchive_project
)
# Import utilities - shared helper functions
from utils.response_helpers import build_response, get_cors_headers
from utils.logging_helpers import get_logger

# ========== LOGGING SETUP =========
logger = get_logger("project_lambda", logging.INFO)

def lambda_handler(request_event, context):
    """
    COMPREHENSIVE API Gateway Lambda entrypoint for project routes with enhanced policy engine integration.
    
    Supports full CRUD operations with comprehensive policy engine authorization:
      - POST   → handle_create_project (with policy engine create permissions)
      - GET    → handle_get_projects (with comprehensive scope filtering)
      - PUT    → handle_update_project (with record-level policy checks)
      - DELETE → handle_delete_project (with batch delete authorization)
    
    Special endpoints:
      - GET /permissions-test → handle_permissions_test (debug endpoint)
    
    Returns structured responses with policy engine metadata and detailed error information.
    """

    http_method = (request_event.get("httpMethod") or "").upper()
    request_path = request_event.get("path", "")
    query_params = request_event.get("queryStringParameters") or {}
    
    # Enhanced: Log request details for debugg
    logger.info(f"🚀 Project Lambda Handler - Method: {http_method}, Path: {request_path}")
    logger.debug(f"Query params: {query_params}")

    # ——— CORS preflight with enhanced headers ———
    if http_method == "OPTIONS":
        logger.debug("Processing CORS preflight request")
        return {
            "statusCode": 200,
            "headers": get_cors_headers(request_event),
            "body": json.dumps({
                "message": "CORS preflight successful",
                "supportedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "policyEngineEnabled": True,
                "timestamp": "2025-09-11 12:15:41"
            }),
        }

    # ——— Parse request body with enhanced error handling ———
    try:
        raw_body = request_event.get("body") or "{}"
        request_body = json.loads(raw_body) if raw_body.strip() else {}
        logger.debug(f"Parsed request body: {len(str(request_body))} characters")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return build_response(
            error=f"Invalid JSON in request body: {str(e)}",
            status=400,
            event=request_event,
        )
    except Exception as e:
        logger.error(f"Body parsing error: {str(e)}")
        return build_response(
            error="Request body parsing failed",
            status=400,
            event=request_event,
        )

    # ——— Extract and validate authorizer context ———
    try:
        authorizer = request_event["requestContext"]["authorizer"]
        requesting_user_id = authorizer["user_id"]
        requesting_user_role = authorizer["role"]
        
        # Enhanced: Additional authorizer context
        requesting_user_name = authorizer.get("user_name", "Unknown")
        requesting_user_privileges = authorizer.get("privileges", [])
        
        logger.info(f"Request by user: {requesting_user_id} ({requesting_user_name}), role: {requesting_user_role}")
        
    except KeyError as e:
        logger.error(f"Missing authorizer field: {str(e)}")
        return build_response(
            error=f"Unauthorized: Missing required authorization field: {str(e)}",
            status=401,
            event=request_event,
        )
    except Exception as e:
        logger.error(f"Authorization parsing error: {str(e)}")
        return build_response(
            error="Unauthorized: Invalid authorization context",
            status=401,
            event=request_event,
        )

    # ——— Enhanced route dispatch with error handling ———
    try:
        # Special debug endpoint
        if (http_method == "GET" and 
            (request_path.endswith("/permissions-test") or query_params.get("debug") == "true")):
            logger.info("Processing permissions test request")
            return handle_permissions_test(request_event, {"user_id": requesting_user_id})

        # Enhanced: Main route handlers with proper signatures
        routes = {
            "POST": lambda: handle_create_project(
                request_event, 
                request_body, 
                requesting_user_id, 
                requesting_user_role, 
                requesting_user_privileges
            ),
            "GET": lambda: handle_get_projects(
                request_event, 
                requesting_user_id, 
                requesting_user_role, 
                requesting_user_privileges
            ),
            "PUT": lambda: handle_update_project(
                request_event, 
                request_body, 
                requesting_user_id, 
                requesting_user_role
            ),
            "DELETE": lambda: _handle_delete_request(
                request_event, 
                request_body, 
                requesting_user_id
            ),
        }

        handler = routes.get(http_method)
        if handler is None:
            logger.warning(f"Unsupported HTTP method: {http_method}")
            return build_response(
                error=f"Method Not Allowed: {http_method} is not supported",
                status=405,
                event=request_event,
                data={
                    "supportedMethods": list(routes.keys()),
                    "requestedMethod": http_method,
                    "endpoint": request_path
                }
            )

        # Enhanced: Execute handler with comprehensive error handling
        logger.info(f"Executing {http_method} handler for user {requesting_user_id}")
        result = handler()
        
        # Enhanced: Add execution metadata to successful responses
        if isinstance(result, dict) and result.get("statusCode", 200) < 400:
            try:
                result_body = json.loads(result.get("body", "{}"))
                if isinstance(result_body, dict):
                    result_body["_meta"] = {
                        "executedAt": "2025-09-11 12:15:41",
                        "executedBy": requesting_user_id,
                        "method": http_method,
                        "policyEngineEnabled": True
                    }
                    result["body"] = json.dumps(result_body)
            except:
                pass  # Don't break response if metadata addition fails
        
        logger.info(f"✅ {http_method} request completed successfully with status {result.get('statusCode', 200)}")
        return result

    except Exception as e:
        # Enhanced error handling with stack trace
        error_id = f"proj-{int(__import__('time').time())}"
        logger.error(f"❌ Unhandled error [{error_id}]: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        
        return build_response(
            error="Internal server error occurred while processing your request",
            status=500,
            event=request_event,
            data={
                "errorId": error_id,
                "timestamp": "2025-09-11 12:15:41",
                "method": http_method,
                "path": request_path,
                "hint": "Check server logs for detailed error information"
            }
        )

def _handle_delete_request(request_event, request_body, requesting_user_id):
    """Route DELETE requests to appropriate handler based on request body"""
    
    action = request_body.get("action")
    if action and action.lower() == "archive":
        logger.info(f"Routing to archive handler for action: {action}")
        return handle_archive_project(request_event, request_body, requesting_user_id, None)
    elif action and action.lower() == "unarchive":
        logger.info(f"Routing to unarchive handler for action: {action}")
        return handle_unarchive_project(request_event, request_body, requesting_user_id, None)
    else:
        # Standard project deletion (including action="delete" or no action)
        logger.info("Routing to standard delete handler")
        return handle_delete_project(request_event, request_body, requesting_user_id, None)

# ========== HEALTH CHECK HANDLER ==========
def health_check_handler(request_event, context):
    """
    Simple health check endpoint for monitoring
    """
    return {
        "statusCode": 200,
        "headers": get_cors_headers(request_event),
        "body": json.dumps({
            "status": "healthy",
            "service": "projects-api",
            "timestamp": "2025-09-11 12:15:41",
            "version": "2.0.0-modular",
            "policyEngine": "enabled",
            "architecture": "modular",
            "features": [
                "comprehensive-authorization",
                "pattern-based-access-control", 
                "batch-operations",
                "debug-endpoints",
                "enhanced-error-handling",
                "modular-architecture"
            ]
        })
    }

# ========== LAMBDA CONFIGURATION METADATA ==========
LAMBDA_CONFIG = {
    "functionName": "projects-api-handler",
    "version": "2.0.0-modular",
    "policyEngineIntegration": "full",
    "supportedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "specialEndpoints": [
        "/permissions-test",
        "/health"
    ],
    "architecture": {
        "handlers": "Request processing and validation",
        "services": "Business logic and external integrations", 
        "models": "Data access and database operations",
        "utils": "Shared utilities and helpers"
    },
    "features": {
        "comprehensiveAuthorization": True,
        "patternBasedAccessControl": True,
        "batchOperations": True,
        "debugEndpoints": True,
        "enhancedErrorHandling": True,
        "corsSupport": True,
        "auditLogging": True,
        "modularArchitecture": True
    }
}

# ========== INITIALIZATION LOG ==========
logger.info("✅ MODULAR Projects Lambda Handler initialized")
logger.info(f"Version: {LAMBDA_CONFIG['version']}")
logger.info(f"Policy Engine: {LAMBDA_CONFIG['policyEngineIntegration']}")
logger.info(f"Supported Methods: {LAMBDA_CONFIG['supportedMethods']}")
logger.info(f"Special Endpoints: {LAMBDA_CONFIG['specialEndpoints']}")
logger.info(f"Architecture: {LAMBDA_CONFIG['architecture']}")
logger.info("🏗️ Modular architecture successfully loaded")
