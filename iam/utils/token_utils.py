"""
Pagination token utilities.
"""
import json
import base64
from typing import Optional, Dict, Any


def encode_token(lek: Optional[Dict[str, Any]]) -> Optional[str]:
    """Encode pagination token."""
    if not lek:
        return None
    raw = json.dumps(lek).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def decode_token(tok: Optional[str]) -> Optional[Dict[str, Any]]:
    """Decode pagination token."""
    if not tok:
        return None
    try:
        raw = base64.urlsafe_b64decode(tok.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None
