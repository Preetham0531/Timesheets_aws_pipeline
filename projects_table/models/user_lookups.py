# -------------------- USER LOOKUP UTILITIES --------------------
from models.database_models import USERS_TABLE, CLIENTS_TABLE, CONTACTS_TABLE
from utils.logging_helpers import get_logger

logger = get_logger(__name__)

def get_user_name(user_id):
    """Get full name of user by ID"""
    if not user_id:
        return "Unknown"
    try:
        user_item = USERS_TABLE.get_item(Key={"userID": user_id}).get("Item")
        if not user_item:
            return user_id
        full_name = f"{user_item.get('firstName','')} {user_item.get('lastName','')}".strip()
        return full_name or user_id
    except Exception:
        return "Unknown"

def get_username(user_id: str) -> str:
    """Get username from USERS_TABLE"""
    if not user_id or not USERS_TABLE:
        return "unknown"
    
    try:
        response = USERS_TABLE.get_item(Key={"userID": user_id})
        user = response.get("Item")
        
        if user and user.get("username"):
            return user["username"]
        
        # Fallback to user_id
        return str(user_id)
        
    except Exception as e:
        logger.warning(f"Error getting username for {user_id}: {e}")
        return str(user_id)

def get_client_name(client_id):
    """Get client company name by ID"""
    if not client_id:
        return "Unknown"
    try:
        client_item = CLIENTS_TABLE.get_item(Key={"clientID": client_id}).get("Item")
        return client_item.get("companyName", client_id) if client_item else client_id
    except Exception:
        return client_id

def get_contact_name(contact_id):
    """Get contact full name by ID"""
    if not contact_id:
        return ""
    try:
        contact_item = CONTACTS_TABLE.get_item(Key={"contactID": contact_id}).get("Item") or {}
        full_name = f"{contact_item.get('firstName','')} {contact_item.get('lastName','')}".strip()
        return full_name
    except Exception:
        return ""