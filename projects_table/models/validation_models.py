# -------------------- ENTITY VALIDATION --------------------
from models.database_models import CLIENTS_TABLE, CONTACTS_TABLE

def validate_contact_and_client(client_id, contact_id=None):
    """Validate client exists and contact belongs to client if provided"""
    try:
        client_item = CLIENTS_TABLE.get_item(Key={"clientID": client_id}).get("Item")
        if not client_item:
            return False, "Client not found"

        if contact_id:
            contact_item = CONTACTS_TABLE.get_item(Key={"contactID": contact_id}).get("Item")
            if not contact_item or contact_item.get("clientID") != client_id or contact_item.get("status") != "Active":
                return False, "Invalid or inactive contact for the given client"

        return True, None
    except Exception:
        return False, "Validation failed"