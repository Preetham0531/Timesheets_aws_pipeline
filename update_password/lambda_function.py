import json
import boto3
import bcrypt
from utils import get_cors_headers, build_response, verify_password, hash_password, CREDENTIALS_TABLE, dynamodb

# Lambda handler for user password reset with explicit CORS via get_cors_headers
def lambda_handler(event, context):
    # Compute CORS headers for every response
    headers = get_cors_headers(event)
    print("headers", headers)

    # 1) CORS preflight support
    if event.get("httpMethod", "").upper() == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({"message": "CORS OK"})
        }

    # 2) Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"error": "Invalid JSON in request body"})
        }

    # 3) Validate required fields
    user_id = body.get("userID", "").strip()
    if not user_id:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"error": "Validation error", "userID": "Required"})
        }

    new_pw = body.get("newPassword", "").strip()
    print("new_pw", new_pw)
    if not new_pw:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"error": "Validation error", "newPassword": "Required new password"})
        }

    # 4) Fetch and verify existing credentials
    cred_resp = CREDENTIALS_TABLE.get_item(Key={"userID": user_id})
    print("cred_resp", cred_resp)
    creds = cred_resp.get("Item")
    print("creds", creds)
    if not creds or "passwordHash" not in creds:
        return {
            "statusCode": 404,
            "headers": headers,
            "body": json.dumps({"error": "Credentials not found"})
        }

    # 5) Hash and update new password
    hashed_pw = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode("utf-8")
    print("new_hash", hashed_pw)
    CREDENTIALS_TABLE.update_item(
        Key={"userID": user_id},
        UpdateExpression="SET passwordHash = :h",
        ExpressionAttributeValues={":h": hashed_pw}
    )

    # 6) Return success
    return {
        "statusCode": 200,
        "headers": headers,
        "body": json.dumps({"message": "Password updated successfully"})
    }
