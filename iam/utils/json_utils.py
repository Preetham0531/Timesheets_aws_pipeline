"""
JSON serialization utilities for DynamoDB types.
"""
from decimal import Decimal
from datetime import date, datetime
from typing import Any


def json_clean(obj: Any) -> Any:
    """
    Recursively convert boto3/DynamoDB types to JSON-safe types.
    """
    if isinstance(obj, dict):
        return {k: json_clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_clean(v) for v in obj]
    if isinstance(obj, set):
        return [json_clean(v) for v in obj]
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    return obj
