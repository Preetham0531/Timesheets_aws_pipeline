"""
Response utilities for API responses and CORS handling.
"""
import json
from typing import Any, Dict, Optional


def get_cors_headers(event: Dict[str, Any]) -> Dict[str, str]:
    """Get CORS headers based on request origin."""
    origin = (event.get("headers", {}) or {}).get("origin", "")
    allowed_origins = [
        "http://localhost:3000",
        "http://192.168.0.224:3000",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://4b5767e1c05f4d0699b39d50c65a9945-b22402c5-3914-4c1f-9db6-bb12c5.projects.builder.codes",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.projects.builder.codes",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.fly.dev"
    ]
    cors_origin = origin if origin in allowed_origins else "null"
    return {
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
    }


def build_response(event: Optional[Dict[str, Any]] = None, data: Any = None, *, 
                   status: int = 200, error: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a standard API response with CORS headers and JSON body.
    """
    headers = get_cors_headers(event or {})
    
    if error:
        body = {"error": error}
        if status == 200:
            status = 400 if error == "Validation error" else 403 if error == "Forbidden" else 401
    else:
        body = data or {}
    
    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body, default=str),
    }
