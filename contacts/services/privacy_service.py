import logging
from typing import Dict, Any, List, Optional, Tuple

from models.user_model import UserModel

# ========= LOGGING =========
logger = logging.getLogger("privacy_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class PrivacyService:
    """
    Service for handling contact privacy settings and user access validation.
    Manages private contacts and allowed users functionality.
    """
    
    def __init__(self):
        self.user_model = UserModel()

    def process_privacy_settings(self, contact_data: Dict[str, Any], user_id: str, 
                                is_create: bool = True, existing_contact: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process privacy settings for contact creation or update
        Returns dict with privacy fields to be saved
        """
        private_setting = contact_data.get("private", False)
        privacy_setting = contact_data.get("privacy", "public")
        allowed_users = contact_data.get("allowedUsers", [])
        
        # Determine if contact should be private
        is_private = False
        if private_setting is not None:
            is_private = bool(private_setting)
        elif privacy_setting is not None:
            is_private = (privacy_setting == "private")
        elif not is_create and existing_contact:
            # For updates, preserve existing privacy setting if not explicitly changed
            existing_private = existing_contact.get("private", False)
            existing_privacy = existing_contact.get("privacy", "public")
            is_private = existing_private or (existing_privacy == "private")
        
        if is_private:
            # Handle private contact
            return self._process_private_contact(allowed_users, user_id, existing_contact, is_create)
        else:
            # Handle public contact
            return self._process_public_contact()

    def can_access_contact(self, user_id: str, contact: Dict[str, Any]) -> bool:
        """
        Check if user can access a contact based on privacy settings
        """
        if not contact:
            return False
        
        # Check privacy settings with backward compatibility
        is_private = contact.get("private", False)
        privacy_value = contact.get("privacy", "public")
        allowed_users = contact.get("allowedUsers", [])
        
        # Backward compatibility: check both old and new privacy fields
        if privacy_value == "private":
            is_private = True
        
        if not is_private:
            # Public contact - always accessible
            return True
        
        # Private contact - check access
        if not allowed_users or not isinstance(allowed_users, list):
            # Malformed private contact - treat as public for backward compatibility
            logger.warning(f"Private contact {contact.get('contactID', 'UNKNOWN')} has invalid allowedUsers - allowing access")
            return True
        
        return user_id in allowed_users

    def filter_contacts_by_privacy(self, contacts: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        """
        Filter list of contacts based on privacy settings
        """
        filtered_contacts = []
        
        for contact in contacts:
            if self.can_access_contact(user_id, contact):
                filtered_contacts.append(contact)
            else:
                logger.debug(f"Excluding private contact {contact.get('contactID', 'UNKNOWN')} - user {user_id} not in allowedUsers")
        
        logger.info(f"Privacy filtering: {len(contacts)} total contacts → {len(filtered_contacts)} accessible to user {user_id}")
        return filtered_contacts

    def get_users_for_privacy(self, search_query: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get list of users available for privacy/allowedUsers selection
        """
        try:
            # Get active users from the system
            users = self.user_model.get_active_users(limit * 2)  # Get more to allow for filtering
            
            # Filter and format users
            filtered_users = []
            for user in users:
                user_id_val = user.get("userID", "")
                first_name = user.get("firstName", "")
                last_name = user.get("lastName", "")
                email = user.get("email", "")
                display_name = f"{first_name} {last_name}".strip() or email or user_id_val
                
                # Apply search filter if provided
                if search_query:
                    searchable_text = f"{first_name} {last_name} {email} {user_id_val}".lower()
                    if search_query not in searchable_text:
                        continue
                
                filtered_users.append({
                    "userID": user_id_val,
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "displayName": display_name,
                    "role": user.get("role", "User")
                })
                
                # Stop when we have enough results
                if len(filtered_users) >= limit:
                    break
            
            logger.info(f"Found {len(filtered_users)} users for privacy selection")
            return filtered_users
            
        except Exception as e:
            logger.error(f"Error fetching users for privacy: {e}")
            return []

    def validate_allowed_users(self, user_ids: List[str]) -> Tuple[List[str], List[str]]:
        """
        Validate that user IDs in allowedUsers actually exist
        Returns: (valid_user_ids, invalid_user_ids)
        """
        if not user_ids or not isinstance(user_ids, list):
            return [], []
        
        valid_users = []
        invalid_users = []
        
        try:
            for user_id in user_ids:
                if not user_id or not isinstance(user_id, str):
                    invalid_users.append(str(user_id))
                    continue
                    
                # Check if user exists in the system
                if self.user_model.user_exists(user_id):
                    valid_users.append(user_id)
                else:
                    invalid_users.append(user_id)
                    logger.warning(f"User {user_id} not found in system")
            
            logger.info(f"User validation: {len(valid_users)} valid, {len(invalid_users)} invalid")
            return valid_users, invalid_users
            
        except Exception as e:
            logger.error(f"Error in user validation: {e}")
            # On error, return all as valid to avoid breaking functionality
            return user_ids, []

    # ========= PRIVATE HELPER METHODS =========

    def _process_private_contact(self, allowed_users: List[str], user_id: str, 
                               existing_contact: Dict[str, Any] = None, is_create: bool = True) -> Dict[str, Any]:
        """Process private contact settings"""
        if not allowed_users or not isinstance(allowed_users, list):
            if is_create:
                allowed_users = [user_id]  # Creator is automatically allowed
            else:
                # For updates, preserve existing allowed users or default to creator
                existing_allowed = existing_contact.get("allowedUsers", []) if existing_contact else []
                if existing_allowed and isinstance(existing_allowed, list):
                    allowed_users = existing_allowed
                else:
                    allowed_users = [user_id]
        elif user_id not in allowed_users:
            allowed_users.append(user_id)  # Ensure creator is always included
        
        # Validate allowed users exist in the system
        valid_users, invalid_users = self.validate_allowed_users(allowed_users)
        if invalid_users:
            logger.warning(f"Invalid user IDs in allowedUsers: {invalid_users}")
            raise Exception(f"Invalid user IDs in allowedUsers: {', '.join(invalid_users)}")
        
        # Use validated users only
        allowed_users = valid_users
        if user_id not in allowed_users:  # Double-check creator is included
            allowed_users.append(user_id)
        
        logger.info(f"Processing private contact with {len(allowed_users)} allowed users")
        
        return {
            "private": True,
            "allowedUsers": allowed_users
        }

    def _process_public_contact(self) -> Dict[str, Any]:
        """Process public contact settings"""
        logger.info("Processing public contact")
        
        return {
            "private": False,
            "allowedUsers": None  # Will be removed/cleaned up in the update
        }

logger.info("✅ PrivacyService initialized")