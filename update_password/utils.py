import os
import jwt
import json
import boto3
import os
import hashlib
import bcrypt
import base64
from datetime import datetime, timedelta
from botocore.exceptions import ClientError



dynamodb = boto3.resource("dynamodb")

CREDENTIALS_TABLE         = dynamodb.Table(os.environ["CREDENTIALS_TABLE"])



def hash_password(password: str) -> str:
    """
    Hash a plaintext password for storage using bcrypt.
    Returns the bcrypt hash as a UTF-8 string.
    """
    # DEBUG: log the incoming password
    print(f"[hash_password] password to hash: {password!r}")

    # Generate salt + hash
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    print(f"[hash_password] hashed bytes: {hashed_bytes!r}")

    # Decode to UTF-8
    hashed_str = hashed_bytes.decode("utf-8")
    print(f"[hash_password] final hash string: {hashed_str}")

    return hashed_str


def verify_password(plaintext: str, hashed: str) -> bool:
    """
    Verify a plaintext password against the stored bcrypt hash.
    """
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # malformed hash
        return False


def build_response(event=None, data=None, *, status=200, error=None, fields=None, cookies=None, plain_text=False):
    headers = get_cors_headers(event) if event else {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true"
    }

    if cookies:
        headers["Set-Cookie"] = cookies

    if plain_text:
        return {
            "statusCode": status,
            "headers": headers,
            "body": data if isinstance(data, str) else str(data)
        }

    body = data if not error else {"error": error}
    if error and fields:
        body.update(fields)

    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body, default=str)
    }



# -------------------- CORS HEADER BUILDER --------------------
def get_cors_headers(event):
    origin = (
        event.get("headers", {}).get("origin") or
        event.get("headers", {}).get("Origin") or
        event.get("multiValueHeaders", {}).get("origin", [None])[0] or
        ""
    ).rstrip("/")

    if not origin:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
            "Access-Control-Allow-Credentials": "true"
        }

    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://test.d2zasimyd0ou3m.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
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
