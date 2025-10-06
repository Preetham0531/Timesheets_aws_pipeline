import json
from user_handlers import *
from employee_handlers import *
from utils import *


# ---- Lambda entry ----
def lambda_handler(event, context):
    method = (event.get("httpMethod") or "").upper()
    headers = get_cors_headers(event)
    authz_ctx = (event.get("requestContext", {}) or {}).get("authorizer", {}) or {}
    user_id = authz_ctx.get("sub") or authz_ctx.get("user_id")

    # --- CORS Preflight ---
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": json.dumps({"ok": True})}

    # --- Method Validation ---
    if method not in {"GET", "POST", "PUT", "DELETE"}:
        return build_response(event, error="Method not allowed", status=405)

    if not user_id:
        return build_response(event, error="missing user identity", status=401)

    try:
        # ===================== GET =====================
        if method == "GET":
            params = event.get("queryStringParameters") or {}
            action = (params.get("action") or "").strip().lower()

            if action == "get-user":
                resp = handle_get_users(event, user_id)

            elif action == "get-employee":
                resp = handleGetEmployees(event, user_id)

            elif action == "get-policies":
                modules_param = (params.get("module") or "").strip()
                if not modules_param:
                    return build_response(event, error="Missing module name(s)", status=400)

                modules = [m.strip() for m in modules_param.split(",") if m.strip()]
                data = get_policies_for_user(user_id, modules)
                if "error" in data:
                    return build_response(event, error=data["error"], status=data.get("status", 400))

                resp = build_response(event, data=data, status=200)

            elif action == "get-user-profile":
                queried_user_id = params.get("userID")
                if not queried_user_id:
                    return build_response(event, error="Missing userID", status=400)
                resp = handleGetUserProfile(event, queried_user_id)

            else:
                # Default → non-login employees
                params["view"] = "nonloginusers"
                event["queryStringParameters"] = params
                resp = handleGetEmployees(event, user_id)


        # ===================== DELETE =====================
        elif method == "DELETE":
            body = json.loads(event.get("body") or "{}")
            action = body.get("action")

            if action == "delete-employee":
                resp = handle_delete_employee(event, user_id)

            elif action == "delete-user":
                resp = handle_delete_user(event, user_id)

            else:
                resp = build_response(event, error=f"Invalid or missing action for DELETE: {action}", status=400)

        # ===================== PUT =====================
        elif method == "PUT":
            body = json.loads(event.get("body") or "{}")
            action = body.get("action")
            target_user_id = body.get("userID") or body.get("employeeID")

            if not target_user_id:
                return build_response(event, error="Missing userID", status=400)

            if action == "update-user":
                resp = update_user_record(event, target_user_id, body, user_id)

            elif action == "update-employee":
                resp = update_employee_record(event, target_user_id, body, user_id)
            
            elif action == "update-employee-profile":
                resp = update_employee_profile(event, target_user_id, body, user_id)

            else:
                resp = build_response(event, error=f"Invalid or missing action for PUT: {action}", status=400)

        # ===================== POST =====================
        elif method == "POST":
            body = json.loads(event.get("body") or "{}")
            action = body.get("action")
            caller_id = authz_ctx.get("user_id")
            if action == "create-employee":
                resp = handle_Create_Employee(event, body, authz_ctx, caller_id)

            elif action == "promote-employee":
                resp = promote_Employee_To_User(event, body, authz_ctx)

            elif action == "signout":
                resp = handle_signout(event, authz_ctx)

            else:
                resp = build_response(event, error=f"Invalid action '{action}'", status=400)

    except json.JSONDecodeError:
        resp = build_response(event, error="Invalid JSON body", status=400)
    except Exception as e:
        resp = build_response(event, error=str(e), status=500)

    # --- Ensure CORS Headers ---
    if isinstance(resp, dict) and "headers" not in resp:
        resp["headers"] = headers

    return resp
