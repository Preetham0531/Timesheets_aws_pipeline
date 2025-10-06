import json
from public_routes import (
    handle_signin,
    handle_forgot_password_request,
    handle_set_password_from_token,
    handle_forgot_password_reset,
    handle_refresh_token
)
from token_utils import get_cors_headers

# --------------------------- MAIN LAMBDA HANDLER ---------------------------
def lambda_handler(event, context):
    try:
        cors_headers = get_cors_headers(event)
        http_method = event.get("httpMethod", "")

        # ——— Handle CORS Preflight ———
        if http_method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": cors_headers,
                "body": json.dumps({"message": "CORS preflight successful"})
            }

        # ——— Only POST Allowed ———
        if http_method != "POST":
            return {
                "statusCode": 405,
                "headers": cors_headers,
                "body": json.dumps({"error": "Method not allowed"})
            }

        # ——— Parse Body & Action ———
        body = json.loads(event.get("body", "{}"))
        action = body.get("action")

        # ——— Action Routing ———
        actions = {
            "signin": handle_signin,
            "forgot-password-request": handle_forgot_password_request,
            "set-password-from-token": handle_set_password_from_token,
            "forgot-password-reset": handle_forgot_password_reset,
            "refresh-token": handle_refresh_token,
        }
        if action not in actions:
            return {
                "statusCode": 400,
                "headers": cors_headers,
                "body": json.dumps({"error": "Invalid action"})
            }

        # ——— Invoke Selected Handler ———
        result = actions[action](event if action == "refresh-token" else body)

        # ——— If Handler Already Returned Full API Response ———
        if isinstance(result, dict) and all(k in result for k in ("statusCode", "headers", "body")):
            result["headers"].update(cors_headers)
            return result

        # ——— Wrap & Return Handler Result ———
        return {
            "statusCode": 200 if "error" not in result else 400,
            "headers": {**cors_headers, **result.get("headers", {})},
            "body": json.dumps(result)
        }

    # ——— Global Exception Handling ———
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": get_cors_headers(event),
            "body": json.dumps({"error": "Server error", "details": str(e)})
        }
