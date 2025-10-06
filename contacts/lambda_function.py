
import json
import logging
import traceback
from typing import Dict, Any

# ========== IMPORT HANDLERS ==========
from handlers.contact_handler import ContactHandler

# ========== IMPORT UTILITIES ==========
from utils import (
    build_response,
    get_cors_headers
)

# ========== LOGGING SETUP ==========
logger = logging.getLogger("contacts_lambda")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def lambda_handler(request_event, context):
    """
    API Gateway Lambda entrypoint for contact routes.
    
    Supports full CRUD operations with policy engine authorization:
      - POST   → create contact
      - GET    → get contacts
      - PUT    → update contact
      - DELETE → delete contact
    
    Special endpoints:
      - GET /permissions-test → debug permissions
      - GET /users → users for privacy selection
    """

    # ——— Derive CORS headers for this request ———
    cors_headers = get_cors_headers(request_event)

    # ——— Helper: build minimal response with CORS ———
    def cors_response(status_code, payload):
        return {
            "statusCode": status_code,
            "headers": cors_headers,
            "body": json.dumps(payload, default=str),
        }

    # ——— Handle CORS preflight ———
    http_method = (request_event.get("httpMethod") or "").upper()
    request_path = request_event.get("path", "")
    query_params = request_event.get("queryStringParameters") or {}
    
    logger.info(f"🚀 Contacts Lambda Handler - Method: {http_method}, Path: {request_path}")

    if http_method == "OPTIONS":
        return cors_response(200, {
            "message": "CORS preflight successful",
            "supportedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "policyEngineEnabled": True,
            "timestamp": "2025-09-12 09:50:36"
        })

    # ——— Extract authorizer context ———
    try:
        authorizer_context = request_event["requestContext"]["authorizer"]
        user_context = {
            "user_id": authorizer_context["user_id"],
            "role": authorizer_context["role"],
            "email": authorizer_context["email"],
        }
        
        logger.info(f"Request by user: {user_context['user_id']} ({user_context.get('email', 'Unknown')}), role: {user_context['role']}")
        
    except Exception as e:
        logger.error(f"Authorization context extraction failed: {str(e)}")
        return cors_response(401, {"error": "Unauthorized"})

    # ——— Parse request body ———
    try:
        raw_body = request_event.get("body") or "{}"
        request_body = json.loads(raw_body) if raw_body.strip() else {}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return cors_response(400, {"error": f"Invalid JSON in request body: {str(e)}"})

    # ——— Route to handlers ———
    try:
        contact_handler = ContactHandler()
        
        # Special debug endpoint
        if (http_method == "GET" and 
            (request_path.endswith("/permissions-test") or query_params.get("debug") == "true")):
            return contact_handler.handle_permissions_test(request_event, user_context)
        
        # Users for privacy selection endpoint
        if (http_method == "GET" and 
            (request_path.endswith("/users") or query_params.get("endpoint") == "users")):
            return contact_handler.handle_get_users_for_privacy(request_event, user_context["user_id"], user_context["role"])

        # Main CRUD handlers
        route_handlers = {
            "POST": lambda: contact_handler.handle_create_contact(
                request_event, 
                request_body, 
                user_context["user_id"], 
                user_context["role"]
            ),
            "GET": lambda: contact_handler.handle_get_contacts(
                request_event, 
                user_context["user_id"], 
                user_context["role"]
            ),
            "PUT": lambda: contact_handler.handle_update_contact(
                request_event, 
                request_body, 
                user_context["user_id"], 
                user_context["role"]
            ),
            "DELETE": lambda: contact_handler.handle_delete_contact(
                request_event, 
                request_body, 
                user_context["user_id"], 
                user_context["role"]
            ),
        }

        selected_handler = route_handlers.get(http_method)
        if selected_handler is None:
            return cors_response(405, {
                "error": "Method Not Allowed",
                "supportedMethods": list(route_handlers.keys()),
                "requestedMethod": http_method
            })

        logger.info(f"Executing {http_method} handler for user {user_context['user_id']}")
        handler_result = selected_handler()

        # Ensure handler result includes headers
        if isinstance(handler_result, dict):
            if "headers" not in handler_result:
                handler_result["headers"] = cors_headers
            else:
                handler_result["headers"].update(cors_headers)
            
            # Add execution metadata to successful responses
            if handler_result.get("statusCode", 200) < 400:
                try:
                    result_body = json.loads(handler_result.get("body", "{}"))
                    if isinstance(result_body, dict):
                        result_body["_meta"] = {
                            "executedAt": "2025-09-12 09:50:36",
                            "executedBy": user_context["user_id"],
                            "method": http_method,
                            "policyEngineEnabled": True
                        }
                        handler_result["body"] = json.dumps(result_body, default=str)
                except:
                    pass  # Don't break response if metadata addition fails

        logger.info(f"✅ {http_method} request completed successfully with status {handler_result.get('statusCode', 200)}")
        return handler_result

    except Exception as e:
        error_id = f"cont-{int(__import__('time').time())}"
        logger.error(f"❌ Unhandled error [{error_id}]: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        
        return cors_response(500, {
            "error": "Internal server error occurred while processing your request",
            "errorId": error_id,
            "timestamp": "2025-09-12 09:50:36",
            "method": http_method,
            "path": request_path,
            "hint": "Check server logs for detailed error information"
        })

def health_check_handler(event, context):
    """
    Simple health check endpoint for monitoring
    """
    cors_headers = get_cors_headers(event)
    return {
        "statusCode": 200,
        "headers": cors_headers,
        "body": json.dumps({
            "status": "healthy",
            "service": "contacts-api",
            "timestamp": "2025-09-12 09:50:36",
            "version": "2.0.0-comprehensive",
            "policyEngine": "enabled",
            "features": [
                "comprehensive-authorization",
                "pattern-based-access-control", 
                "batch-operations",
                "debug-endpoints",
                "enhanced-error-handling"
            ]
        }, default=str)
    }

logger.info("✅ COMPREHENSIVE Contacts Lambda Handler initialized")