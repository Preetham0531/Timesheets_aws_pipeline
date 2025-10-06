# Main Lambda entrypoint - routes requests to appropriate handlers
import json
import logging
import traceback
from typing import Dict, Any

# Import handlers
from handlers.approval_handlers import (
    handle_raise_approval,
    handle_update_approval, 
    handle_get_approval_summary,
    handle_permissions_test
)
from utils import get_cors_headers

# Logging setup
logger = logging.getLogger("approval_lambda")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def lambda_handler(request_event, context):
    """
    Main Lambda entrypoint for approval workflow routes.
    Routes requests to appropriate handlers based on HTTP method and action.
    """
    cors_headers = get_cors_headers(request_event)

    def cors_response(status_code, payload):
        return {
            "statusCode": status_code,
            "headers": cors_headers,
            "body": json.dumps(payload, default=str),
        }

    http_method = (request_event.get("httpMethod") or "").upper()
    request_path = request_event.get("path", "")
    query_params = request_event.get("queryStringParameters") or {}
    
    logger.info(f"🚀 Approval Lambda Handler - Method: {http_method}, Path: {request_path}")

    if http_method == "OPTIONS":
        return cors_response(200, {
            "message": "CORS preflight successful",
            "supportedMethods": ["GET", "POST", "OPTIONS"],
            "supportedActions": {
                "GET": ["summary", "permissions-test"],
                "POST": ["raise", "update"]
            },
            "policyEngineEnabled": True
        })

    # Extract authorizer context
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

    # Parse request body for POST methods
    try:
        raw_body = request_event.get("body") or "{}"
        request_body = json.loads(raw_body) if raw_body.strip() else {}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return cors_response(400, {"error": f"Invalid JSON in request body: {str(e)}"})

    # Route to appropriate handlers
    try:
        # Special debug endpoint
        if (http_method == "GET" and 
            (request_path.endswith("/permissions-test") or query_params.get("debug") == "true")):
            return handle_permissions_test(request_event, user_context)

        # Main route handlers
        if http_method == "GET":
            action = (query_params.get("action") or "").strip().lower()
            if action == "summary" or not action:
                handler_result = handle_get_approval_summary(request_event, user_context)
            else:
                return cors_response(400, {
                    "error": f"Unsupported GET action: {action}",
                    "supportedActions": ["summary"]
                })

        elif http_method == "POST":
            action = request_body.get("action", "").strip().lower()
            if action == "raise":
                handler_result = handle_raise_approval(request_event, request_body, user_context)
            elif action == "update":
                handler_result = handle_update_approval(request_event, request_body, user_context)
            else:
                return cors_response(400, {
                    "error": f"Invalid or missing action: {action}",
                    "supportedActions": ["raise", "update"]
                })

        else:
            return cors_response(405, {
                "error": f"Method Not Allowed: {http_method}",
                "supportedMethods": ["GET", "POST", "OPTIONS"]
            })

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
                            "executedBy": user_context["user_id"],
                            "method": http_method,
                            "action": query_params.get("action") or request_body.get("action", "unknown"),
                            "policyEngineEnabled": True
                        }
                        handler_result["body"] = json.dumps(result_body, default=str)
                except:
                    pass

        logger.info(f"✅ {http_method} request completed successfully with status {handler_result.get('statusCode', 200)}")
        return handler_result

    except Exception as e:
        error_id = f"appr-{int(__import__('time').time())}"
        logger.error(f"❌ Unhandled error [{error_id}]: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        
        return cors_response(500, {
            "error": "Internal server error occurred while processing your request",
            "errorId": error_id,
            "method": http_method,
            "path": request_path
        })

def health_check_handler(event, context):
    """Health check endpoint for monitoring"""
    cors_headers = get_cors_headers(event)
    return {
        "statusCode": 200,
        "headers": cors_headers,
        "body": json.dumps({
            "status": "healthy",
            "service": "approvals-api",
            "version": "2.0.0-modular"
        }, default=str)
    }

logger.info("✅ Approval Lambda Handler initialized (modular structure)")