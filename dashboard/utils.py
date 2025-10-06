import json
import boto3
from boto3.dynamodb.conditions import Attr
import re
from datetime import datetime, timedelta, date

def get_cors_headers(event):
    origin = event.get("headers", {}).get("origin") or ""
    allowed_origins = [
        "http://localhost:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://timesheets.qa.inferai.ai",
        "https://www.timesheets.qa.inferai.ai",
        "http://localhost:48752",
"https://www.timesheets.test.inferai.ai",
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


def build_response(data=None, *, status=200, error=None, message=None, fields=None, error_code=None, event=None):
    body = {"success": error is None}

    if message:
        body["message"] = message
    if error:
        body["error"] = error
        if error_code:
            body["errorCode"] = error_code
        if fields:
            body["fields"] = fields
    elif data is not None:
        body["data"] = data

    return {
        "statusCode": status,
        "headers": get_cors_headers(event or {}),
        "body": json.dumps(body, default=str)
    }