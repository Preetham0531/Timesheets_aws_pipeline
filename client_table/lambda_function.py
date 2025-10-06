import json
from handlers.client_handler import (
    handle_create,
    handle_get,
    handle_update,
    handle_delete,
)
from utils import build_response, get_cors_headers

def lambda_handler(request_event, context):
    """
    API Gateway Lambda entrypoint for client CRUD routes.
    Applies CORS headers, validates authorizer context, and dispatches to:
      - POST   → handle_create
      - GET    → handle_get
      - PUT    → handle_update
      - DELETE → handle_delete
    Returns 401 when authorizer context is missing, 405 for unsupported methods,
    and 500 for unhandled errors. Ensures responses include CORS headers.
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
    if http_method == "OPTIONS":
        return cors_response(200, {"message": "CORS preflight successful"})

    # ——— Extract authorizer context (Unauthorized if missing) ———
    try:
        authorizer_context = request_event["requestContext"]["authorizer"]
        user_context = {
            "user_id": authorizer_context["user_id"],
            "role": authorizer_context["role"],
            "email": authorizer_context["email"],
        }
    except Exception:
        return cors_response(401, {"error": "Unauthorized"})

    # ——— Dispatch request to appropriate CRUD handler ———
    try:
        route_handlers = {
            "POST": handle_create,
            "GET": handle_get,
            "PUT": handle_update,
            "DELETE": handle_delete,
        }

        selected_handler = route_handlers.get(http_method)
        if selected_handler is None:
            return cors_response(405, {"error": "Method Not Allowed"})

        handler_result = selected_handler(request_event, user_context)

        # Ensure handler result includes headers for consistency
        if isinstance(handler_result, dict) and "headers" not in handler_result:
            handler_result["headers"] = cors_headers

        return handler_result

    except Exception:
        return cors_response(500, {"error": "Internal server error"})
