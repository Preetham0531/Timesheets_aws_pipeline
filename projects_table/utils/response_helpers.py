# -------------------- RESPONSE UTILITIES --------------------
import json
from typing import Dict, Any, Optional

def get_cors_headers(event):
    """Generate CORS headers based on request origin"""
    headers = (event.get("headers") or {}) if isinstance(event, dict) else {}
    origin = headers.get("origin") or headers.get("Origin") or ""
    allowed_origins = {
        "http://localhost:3000",
        "http://192.168.0.224:3000",
        "https://test.d33utl6pegyzdw.amplifyapp.com",
        "https://test-copy.dqa87374qqtdj.amplifyapp.com",
        "https://development-env.d2zasimyd0ou3m.amplifyapp.com",
        "https://timesheets.test.inferai.ai",
        "https://e869fba69ba8426ab8b34c6ded2c23da-e22ca7a4542b4afd8f475d97e.fly.dev",
        "https://www.timesheets.test.inferai.ai",
        "https://timesheets.dev.inferai.ai",
        "https://www.timesheets.dev.inferai.ai",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.projects.builder.codes",
        "https://566934dad88c4e72af5b4cc88d847050-1020e2b7-d338-4e38-b86f-cee89d.fly.dev"
    }
    return {
        "Access-Control-Allow-Origin": origin if origin in allowed_origins else "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }

def build_response(data=None, *, status=200, error=None, event=None):
    """Build standardized API response"""
    return {
        "statusCode": status,
        "headers": get_cors_headers(event or {}),
        "body": json.dumps({"error": error} if error else (data or {}), default=str),
    }