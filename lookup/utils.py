import json

# -------------------- CORS Headers --------------------
def get_cors_headers(event):
    origin = event.get("headers", {}).get("origin") or ""
    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://test.timesheets.inferai.ai",
        "https://labs.inferai.ai",
        "https://www.labs.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "https://www.test.timesheets.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.projects.builder.codes",
        "https://e4ed101c89c94e53b145538bf7b38f07-6bc392b3-9894-484e-aef1-808c64.fly.dev"
    ]
    if origin in allowed_origins:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
            "Access-Control-Allow-Credentials": "true"
        }
    return {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true"
    }

# Standard JSON response builder
def build_response(data=None, *, status=200, error=None, message=None, error_code=None, event=None):
    body = {}
    if message:
        body["message"] = message
    if error:
        body["error"] = error
        if error_code:
            body["errorCode"] = error_code
    elif data is not None:
        body["data"] = data
    return {
        "statusCode": status,
        "headers": get_cors_headers(event or {}),
        "body": json.dumps(body, default=str)
    }

# Privilege check helper (takes event to preserve CORS)
def authorize_action(user_id, role, privilege, table, event):
    result = table.get_item(Key={"userID": user_id})
    if "Item" not in result:
        return build_response(event=event, error="Role privileges not found.", status=403)
    privileges = result["Item"].get("privileges", [])
    normalized_privileges = normalize_privileges(privileges)
    normalized = normalize_privileges([privilege])
    if not normalized:
        return build_response(event=event, error=f"Invalid privilege code/name: '{privilege}'", status=403)
    required_code = normalized[0]
    if required_code in normalized_privileges:
        return None
    return build_response(event=event, error=f"Missing privilege '{required_code}'", status=403)
