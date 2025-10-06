"""
Main Lambda function handler - Entry point for IAM Roles API.

This module serves as the primary entry point for the Lambda function,
routing HTTP requests to appropriate handlers based on the HTTP method.

Architecture:
- Entry Point: lambda_handler validates and routes requests
- Handlers: Parse and validate input, extract parameters
- Services: Business logic and orchestration
- Models: Data access layer
- Utils: Shared utilities and helpers
"""
from typing import Any, Dict
from logging_config import create_logger
from policy_integration import POLICY_ENGINE_AVAILABLE
from handlers import (
    handle_options_request,
    handle_post_request,
    handle_get_request,
    handle_put_request,
    handle_delete_request,
    extract_caller_identity
)
from utils import build_response

logger = create_logger("roles.lambda_handler")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for IAM Roles API.
    
    Routes requests based on HTTP method:
    - OPTIONS: CORS preflight and API metadata
    - POST: Create new roles
    - GET: Retrieve roles (list or specific)
    - PUT: Update roles (global or user-specific customization)
    - DELETE: Soft-delete or hard-delete roles
    
    Query Parameters:
    - user_id/userId: Target user for customization operations
    - rid: Role ID for specific operations
    - role: Role name for lookup
    - status: Filter by role status
    - limit: Pagination limit
    - nextToken: Pagination token
    
    Args:
        event: Lambda event with HTTP request data
        context: Lambda context object
        
    Returns:
        HTTP response with status code, headers, and JSON body
    """
    method = (event.get("httpMethod") or "").upper()
    query_params = event.get("queryStringParameters") or {}
    target_user_id = query_params.get("user_id") or query_params.get("userId")
    operation_type = "user_customization" if target_user_id else "global_role"
    
    logger.info(f"Roles Lambda Handler - Method: {method}, Type: {operation_type}")
    if target_user_id:
        logger.info(f"Target user for customization: {target_user_id}")
    
    # Handle OPTIONS request (CORS preflight)
    if method == "OPTIONS":
        return handle_options_request(event)
    
    # Extract and validate caller identity
    caller_id, error_response = extract_caller_identity(event)
    if error_response:
        return error_response
    
    logger.info(f"Request by user: {caller_id} ({operation_type})")
    
    # Route to appropriate handler based on HTTP method
    try:
        if method == "POST":
            return handle_post_request(event, caller_id)
        elif method == "GET":
            return handle_get_request(event, caller_id)
        elif method == "PUT":
            return handle_put_request(event, caller_id)
        elif method == "DELETE":
            return handle_delete_request(event, caller_id)
        else:
            return build_response(
                event=event,
                error="Method Not Allowed. Use GET, POST, PUT, or DELETE.",
                status=405
            )
    except Exception as e:
        logger.exception("Unhandled error in lambda_handler")
        return build_response(
            event=event,
            error="Internal server error",
            status=500
        )


# Initialization logging
logger.info("IAM Roles Lambda Handler initialized")
logger.info(f"Policy engine available: {POLICY_ENGINE_AVAILABLE}")
logger.info(f"Supports user-specific role customizations: True")
