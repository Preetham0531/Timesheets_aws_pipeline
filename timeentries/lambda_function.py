import json
from backtrack_routes import (
    handle_backtrack_request,
    handle_backtrack_approval
)
from time_entry_routes import (
    handle_create_or_update,
    handle_delete_entries,
    handle_time_summary,
    handle_get_filter_data,
    handle_get_users,
    handle_user_projects_and_tasks
)
from pto_routes import (
    handle_pto_request,
    handle_pto_approval
)
from utils import build_response, get_cors_headers


# -------------------------------
# Lambda Handler
# -------------------------------
def lambda_handler(event, context):
    """
    Main Lambda entrypoint for all time entry and approval related routes.
    - Handles CORS, authentication, routing for GET/POST/DELETE methods.
    - Delegates to route handlers according to action.
    - Ensures unified error responses and CORS headers.
    """
    try:
        method = event.get("httpMethod", "").upper()
        response = None

        # ----------------- CORS Preflight -----------------
        if method == "OPTIONS":
            return build_response(data={"message": "CORS preflight successful"}, event=event)

        # ----------------- Extract Auth Context -----------------
        try:
            authorizer = event["requestContext"]["authorizer"]
            auth = {
                "user_id": authorizer.get("user_id"),
                "email": authorizer.get("email"),
                "role": authorizer.get("role", "").lower(),
                "privileges": json.loads(authorizer.get("privileges", "[]"))
            }
        except Exception as e:
            return build_response(
                error="Unauthorized",
                fields={"auth": str(e)},
                status=401,
                event=event
            )

        # ----------------- Extract Body & Query Params -----------------
        try:
            body = json.loads(event.get("body", "{}")) if event.get("body") else {}
        except Exception:
            return build_response(
                error="Validation error",
                fields={"body": "Invalid JSON"},
                status=400,
                event=event
            )

        action = body.get("action", "")
        params = event.get("queryStringParameters") or {}

        # ----------------- GET Routes -----------------
        if method == "GET":
            get_action = (params.get("action") or "").strip().lower()

            if get_action == "getfilterdata":
                response = handle_get_filter_data(event, auth)
            elif get_action == "gettimesummary":
                response = handle_time_summary(event, auth)
            elif get_action == "usersdata":
                response = handle_get_users(event, auth)
            elif get_action == "getprojects":
                response = handle_user_projects_and_tasks(event, auth)
            else:
                return build_response(error="Invalid GET action", status=400, event=event)

        # ----------------- POST Routes -----------------
        elif method == "POST":
            if action == "createOrUpdateEntry":
                response = handle_create_or_update(event, auth)
            elif action == "raiseBacktrack":
                response = handle_backtrack_request(event, auth)
            elif action == "approveBacktrack":
                response = handle_backtrack_approval(event, auth)
            elif action == "submitPTO":
                response = handle_pto_request(body, auth)
            elif action == "approvePTO":
                response = handle_pto_approval(body, auth)
            else:
                return build_response(error="Invalid POST action", status=400, event=event)

        # ----------------- DELETE Route -----------------
        elif method == "DELETE":
            response = handle_delete_entries(event, body, auth)

        else:
            return build_response(error="Method not allowed", status=405, event=event)

    except Exception as e:
        print(f"[lambda_handler] Error: {str(e)}")
        return build_response(error="Internal server error", status=500, event=event)

    # ----------------- Finalize Response -----------------
    # Attach CORS headers if not already set
    if isinstance(response, dict) and "headers" not in response:
        response["headers"] = build_response(event=event)["headers"]
    return response
