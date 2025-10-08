import json
import logging
from utils import get_cors_headers
from task_function import (
    handle_add_task,
    handle_update_task,
    handle_delete_task,
    handle_get_tasks,
)


# ——— Lambda Handler ———
def lambda_handler(event, context):
    logger = logging.getLogger(__name__)
    logger.info("tasks.lambda_handler invoked")
    logger.info("request_id=%s", getattr(context, "aws_request_id", "N/A"))

    # Get HTTP method and CORS headers
    method = event.get("httpMethod", "").upper()
    headers = get_cors_headers(event)

    # CORS preflight
    if method == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({"message": "CORS preflight success"})
        }

    # Auth extraction
    try:
        auth = event["requestContext"]["authorizer"]
        user_id = auth.get("user_id")
    except Exception as e:
        return {
            "statusCode": 401,
            "headers": headers,
            "body": json.dumps({
                "error": "Unauthorized",
                "fields": {"auth": str(e)}
            })
        }

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        body = {}

    # Route by HTTP method
    if method == "POST":
        response = handle_add_task(body, user_id, event)
    elif method == "PUT":
        response = handle_update_task(body, user_id, event)
    elif method == "DELETE":
        response = handle_delete_task(body, user_id, event)
    elif method == "GET":
        response = handle_get_tasks(event, user_id)
    else:
        response = build_response(error="Method Not Allowed", status=405, event=event)

    # Always apply CORS headers
    if isinstance(response, dict) and "headers" not in response:
        response["headers"] = headers

    return response
