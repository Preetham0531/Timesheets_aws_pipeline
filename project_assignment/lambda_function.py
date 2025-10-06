import json
from assignment_routes import (
    handle_assign_multiple_users,
    handle_delete_assignment,
    handle_get_project_user_assignments,
    handle_update_assignment,
    handle_get_unassigned_members,
)
from utils import build_response, get_cors_headers


# ——— Lambda Handler ———
def lambda_handler(request_event, context):

    # CORS preflight
    http_method = (request_event.get("httpMethod") or "").upper()
    if http_method == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": get_cors_headers(request_event),
            "body": json.dumps({"message": "CORS preflight successful"}),
        }

    # Authorization context
    try:
        authorizer_context = request_event["requestContext"]["authorizer"]
        print(f"Authorizer context: {authorizer_context}")
        requesting_user_id = authorizer_context["user_id"]
    except Exception:
        return build_response(error="Unauthorized", status=401, event=request_event)

    # Parse request body
    try:
        request_body = json.loads(request_event.get("body") or "{}")
    except Exception:
        return build_response(error="Invalid JSON", status=400, event=request_event)

    # Extract query params
    action_query = ((request_event.get("queryStringParameters") or {}).get("action") or "").lower()

    # Route dispatcher
    route_handlers = {
        "POST": lambda: handle_assign_multiple_users(
            request_event, request_body, requesting_user_id
        ),
        "PUT": lambda: handle_update_assignment(
            request_event, request_body, requesting_user_id
        ),
        "DELETE": lambda: handle_delete_assignment(
            request_event, requesting_user_id, request_body
        ),
        "GET": (
            lambda: handle_get_unassigned_members(
                request_event, requesting_user_id
            )
            if action_query == "unassigned"
            else handle_get_project_user_assignments(
                request_event, requesting_user_id
            )
        ),
    }

    # Fallback for unsupported methods
    selected_handler = route_handlers.get(http_method)
    if selected_handler is None:
        return build_response(error="Method not allowed", status=405, event=request_event)

    # Call the selected handler
    return selected_handler()
