import logging
from typing import Dict, Any, List, Optional
from boto3.dynamodb.conditions import Attr, Key

from utils import CONTACTS_TABLE, EMPLOYEES_TABLE

# ========= LOGGING =========
logger = logging.getLogger("contact_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ========= CONSTANTS =========
BATCH_SIZE = 100

class ContactModel:
    """
    Data access layer for contact operations.
    Handles all database interactions for contacts.
    """
    
    def __init__(self):
        self.contacts_table = CONTACTS_TABLE
        self.employees_table = EMPLOYEES_TABLE

    def create_contact(self, contact_item: Dict[str, Any]) -> None:
        """Create a new contact in the database"""
        try:
            self.contacts_table.put_item(Item=contact_item)
            logger.info(f"✅ Created contact {contact_item['contactID']} in database")
        except Exception as e:
            logger.error(f"Failed to create contact in database: {e}")
            raise

    def get_contact_by_id(self, contact_id: str) -> Optional[Dict[str, Any]]:
        """Get a contact by ID"""
        try:
            response = self.contacts_table.get_item(Key={"contactID": contact_id})
            return response.get("Item")
        except Exception as e:
            logger.error(f"Error fetching contact {contact_id}: {e}")
            return None

    def update_contact(self, contact_id: str, update_expressions: List[str], 
                      expression_values: Dict[str, Any], expression_names: Dict[str, str]) -> Dict[str, Any]:
        """Update a contact in the database"""
        try:
            update_request = {
                "Key": {"contactID": contact_id},
                "UpdateExpression": "SET " + ", ".join(update_expressions),
                "ExpressionAttributeValues": expression_values,
                "ExpressionAttributeNames": expression_names,
                "ReturnValues": "ALL_NEW"
            }
            
            response = self.contacts_table.update_item(**update_request)
            updated_item = response.get("Attributes", {})
            
            logger.info(f"✅ Updated contact {contact_id} in database")
            return updated_item
            
        except Exception as e:
            logger.error(f"Failed to update contact {contact_id}: {e}")
            raise

    def delete_contact(self, contact_id: str) -> None:
        """Delete a contact from the database"""
        try:
            self.contacts_table.delete_item(Key={"contactID": contact_id})
            logger.info(f"✅ Deleted contact {contact_id} from database")
        except Exception as e:
            logger.error(f"Failed to delete contact {contact_id}: {e}")
            raise

    def delete_related_employee_record(self, contact_id: str) -> None:
        """Delete related employee record if it exists"""
        try:
            self.employees_table.delete_item(Key={"employeeID": contact_id})
            logger.info(f"Deleted related employee record for contact {contact_id}")
        except Exception as e:
            logger.warning(f"Error deleting employee record for contact {contact_id}: {e}")
            # Don't raise - this is optional cleanup

    def email_exists_for_client(self, email: str, client_id: str, exclude_contact_id: str = None) -> bool:
        """Check if email already exists for a specific client"""
        try:
            scan_result = self.contacts_table.scan(
                FilterExpression=Attr("clientID").eq(client_id) & Attr("officialEmail").eq(email)
            )
            items = scan_result.get("Items", [])
            
            if exclude_contact_id:
                items = [item for item in items if item.get("contactID") != exclude_contact_id]
            
            return len(items) > 0
            
        except Exception as e:
            logger.error(f"Error checking duplicate email '{email}' for client {client_id}: {e}")
            return True  # Err on the side of caution

    def scan_all_contacts(self) -> List[Dict[str, Any]]:
        """Scan all contacts from the table"""
        try:
            all_items = []
            
            logger.info("Starting scan of all contacts...")
            response = self.contacts_table.scan()
            initial_items = response.get("Items", [])
            all_items.extend(initial_items)
            
            logger.info(f"First scan page: {len(initial_items)} contacts")
            
            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = self.contacts_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                page_items = response.get("Items", [])
                all_items.extend(page_items)
                logger.debug(f"Additional page: {len(page_items)} contacts")
            
            logger.info(f"✅ Total contacts scanned: {len(all_items)}")
            return all_items
            
        except Exception as e:
            logger.error(f"Error scanning contacts: {e}")
            return []

    def get_contacts_by_client(self, client_id: str) -> List[Dict[str, Any]]:
        """Get all contacts for a specific client"""
        try:
            all_items = []
            response = self.contacts_table.scan(
                FilterExpression=Attr("clientID").eq(client_id)
            )
            all_items.extend(response.get("Items", []))
            
            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = self.contacts_table.scan(
                    FilterExpression=Attr("clientID").eq(client_id),
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                all_items.extend(response.get("Items", []))
            
            logger.debug(f"Found {len(all_items)} contacts for client {client_id}")
            return all_items
            
        except Exception as e:
            logger.error(f"Error querying contacts by client {client_id}: {e}")
            return []

    def batch_get_contacts_by_ids(self, contact_ids: List[str]) -> List[Dict[str, Any]]:
        """Get multiple contacts by their IDs"""
        if not contact_ids:
            return []
        
        logger.info(f"Fetching {len(contact_ids)} contacts by IDs")
        
        all_items = []
        
        for i in range(0, len(contact_ids), BATCH_SIZE):
            chunk_ids = contact_ids[i:i+BATCH_SIZE]
            logger.debug(f"Processing chunk {i//BATCH_SIZE + 1}: {len(chunk_ids)} contacts")
            
            try:
                for contact_id in chunk_ids:
                    resp = self.contacts_table.get_item(Key={"contactID": contact_id})
                    item = resp.get("Item")
                    if item:
                        all_items.append(item)
                    else:
                        logger.warning(f"Contact {contact_id} not found")
            except Exception as e:
                logger.error(f"Error fetching contacts in chunk {i//BATCH_SIZE + 1}: {e}")
        
        logger.info(f"Batch get result: {len(all_items)} items retrieved from {len(contact_ids)} requested")
        return all_items

    def get_contacts_by_creators(self, creator_user_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Get all contacts created by specific users
        Uses GSI if available, falls back to scan
        """
        if not creator_user_ids:
            return []
        
        logger.info(f"Fetching contacts created by {len(creator_user_ids)} creators")
        
        all_contacts = []
        
        for creator_id in creator_user_ids:
            try:
                # Try GSI first (more efficient)
                try:
                    logger.debug(f"Querying contacts created by {creator_id} using GSI")
                    
                    response = self.contacts_table.query(
                        IndexName='createdBy-index',
                        KeyConditionExpression=Key('createdBy').eq(creator_id)
                    )
                    
                    creator_contacts = response.get("Items", [])
                    all_contacts.extend(creator_contacts)
                    
                    logger.info(f"GSI query for creator {creator_id}: found {len(creator_contacts)} contacts")
                    
                    # Handle pagination
                    while response.get("LastEvaluatedKey"):
                        response = self.contacts_table.query(
                            IndexName='createdBy-index',
                            KeyConditionExpression=Key('createdBy').eq(creator_id),
                            ExclusiveStartKey=response["LastEvaluatedKey"]
                        )
                        additional_contacts = response.get("Items", [])
                        all_contacts.extend(additional_contacts)
                        logger.debug(f"GSI pagination: got {len(additional_contacts)} additional contacts")
                
                except Exception as gsi_error:
                    # Fallback to scan
                    logger.warning(f"GSI query failed for creator {creator_id}, falling back to scan: {gsi_error}")
                    
                    scan_response = self.contacts_table.scan(
                        FilterExpression=Attr('createdBy').eq(creator_id)
                    )
                    
                    creator_contacts = scan_response.get("Items", [])
                    all_contacts.extend(creator_contacts)
                    
                    logger.info(f"Scan fallback for creator {creator_id}: found {len(creator_contacts)} contacts")
                    
                    # Handle pagination for scan
                    while scan_response.get("LastEvaluatedKey"):
                        scan_response = self.contacts_table.scan(
                            FilterExpression=Attr('createdBy').eq(creator_id),
                            ExclusiveStartKey=scan_response["LastEvaluatedKey"]
                        )
                        additional_contacts = scan_response.get("Items", [])
                        all_contacts.extend(additional_contacts)
                        logger.debug(f"Scan pagination: got {len(additional_contacts)} additional contacts")
                
            except Exception as e:
                logger.error(f"Error fetching contacts for creator {creator_id}: {e}")
        
        logger.info(f"Total contacts from {len(creator_user_ids)} creators: {len(all_contacts)}")
        return all_contacts

logger.info("✅ ContactModel initialized")