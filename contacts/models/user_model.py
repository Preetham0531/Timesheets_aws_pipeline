import logging
from typing import Dict, Any, List
from boto3.dynamodb.conditions import Attr

from utils import USERS_TABLE

# ========= LOGGING =========
logger = logging.getLogger("user_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class UserModel:
    """
    Data access layer for user operations.
    Handles database interactions for users.
    """
    
    def __init__(self):
        self.users_table = USERS_TABLE

    def user_exists(self, user_id: str) -> bool:
        """Check if a user exists in the system"""
        try:
            response = self.users_table.get_item(Key={"userID": user_id})
            return "Item" in response
        except Exception as e:
            logger.error(f"Error checking if user {user_id} exists: {e}")
            return False

    def get_user_by_id(self, user_id: str) -> Dict[str, Any]:
        """Get a user by ID"""
        try:
            response = self.users_table.get_item(Key={"userID": user_id})
            return response.get("Item")
        except Exception as e:
            logger.error(f"Error fetching user {user_id}: {e}")
            return None

    def get_active_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of active users"""
        try:
            # Scan for active users
            scan_params = {
                "FilterExpression": Attr("status").eq("Active"),
                "Limit": limit
            }
            
            response = self.users_table.scan(**scan_params)
            users = response.get("Items", [])
            
            logger.debug(f"Found {len(users)} active users")
            return users
            
        except Exception as e:
            logger.error(f"Error fetching active users: {e}")
            return []

logger.info("✅ UserModel initialized")