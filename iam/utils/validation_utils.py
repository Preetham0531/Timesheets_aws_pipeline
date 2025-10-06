"""
Validation utilities for user IDs and other inputs.
"""
import uuid


def is_valid_user_id(user_id: str) -> bool:
    """Validate if a user ID is in valid format (UUID or alphanumeric)."""
    try:
        uuid.UUID(user_id)
        return True
    except ValueError:
        return bool(user_id and isinstance(user_id, str) and 8 <= len(user_id) <= 64 and user_id.isalnum())
