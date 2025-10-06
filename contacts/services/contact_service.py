import logging
import uuid
import traceback
from datetime import datetime
from typing import Dict, Any, List, Optional

from models.contact_model import ContactModel
from models.project_model import ProjectModel
from services.authorization_service import AuthorizationService
from services.privacy_service import PrivacyService
from utils import (
    generate_unique_display_id,
    get_username,
    get_user_name,
    build_response,
    format_date,
    get_client_name
)

# ========= LOGGING =========
logger = logging.getLogger("contact_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ========= CONSTANTS =========
UPDATABLE_FIELDS = [
    "firstName", "lastName", "designation", "officialEmail", "secondaryEmail",
    "phoneNumber", "clientID", "projectID", "notes", "status",
    "street1", "street2", "city", "state", "country", "zip",
    "private", "privacy", "allowedUsers"
]

class ContactService:
    """
    Business logic for contact operations.
    Handles creation, updates, deletion, and retrieval with privacy and authorization.
    """
    
    def __init__(self):
        self.contact_model = ContactModel()
        self.project_model = ProjectModel()
        self.auth_service = AuthorizationService()
        self.privacy_service = PrivacyService()

    def create_contact(self, contact_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """
        Create a new contact with privacy settings
        """
        # Generate unique IDs and timestamp
        contact_id = str(uuid.uuid4())
        created_at_iso = datetime.utcnow().isoformat()
        username = get_username(user_id)
        
        try:
            contact_display_id = generate_unique_display_id("CONT")
        except Exception as e:
            logger.error(f"Display ID generation failed: {e}")
            raise Exception(f"ID generation failed: {str(e)}")

        # Build base contact record
        contact_item = {
            "contactID": contact_id,
            "displayID": contact_display_id,
            "firstName": contact_data["firstName"].strip(),
            "lastName": contact_data.get("lastName", "").strip(),
            "designation": contact_data.get("designation", ""),
            "officialEmail": contact_data["officialEmail"].strip(),
            "secondaryEmail": contact_data.get("secondaryEmail", ""),
            "phoneNumber": contact_data.get("phoneNumber", ""),
            "street1": contact_data.get("street1", ""),
            "street2": contact_data.get("street2", ""),
            "city": contact_data.get("city", ""),
            "state": contact_data.get("state", ""),
            "country": contact_data.get("country", ""),
            "zip": contact_data.get("zip", ""),
            "loginEnabled": False,
            "clientID": contact_data["clientID"],
            "notes": contact_data.get("notes", ""),
            "status": contact_data.get("status", "Active"),
            "createdAt": created_at_iso,
            "createdBy": user_id,
            "createdByName": username,
            "updatedByName": username,
            "updatedAt": created_at_iso,
            "updatedBy": user_id,
            "role": "Contact",
        }

        # Handle privacy settings (allowedUsers NOT mandatory; ensure creator is included if private)
        privacy_result = self.privacy_service.process_privacy_settings(
            contact_data, user_id, is_create=True
        )

        # --- Enforce creator access for private contacts ---
        try:
            is_private = bool(privacy_result.get("private", False))
            if is_private:
                raw_allowed = privacy_result.get("allowedUsers", None)
                if raw_allowed is None or not isinstance(raw_allowed, list) or len(raw_allowed) == 0:
                    # No list provided or empty → default to creator only
                    privacy_result["allowedUsers"] = [str(user_id)]
                else:
                    # Normalize to strings, dedupe, and ensure creator present
                    norm = [str(uid).strip() for uid in raw_allowed if str(uid).strip()]
                    if str(user_id) not in norm:
                        norm.append(str(user_id))
                    privacy_result["allowedUsers"] = sorted(set(norm))
            else:
                # Public contact → clear allowedUsers if present (keeps storage consistent)
                privacy_result["allowedUsers"] = []
        except Exception as e:
            logger.warning(f"Privacy enforcement normalization error: {e}")
            # Fail-safe: if private, at least ensure creator; else leave as public
            if bool(privacy_result.get("private", False)):
                privacy_result["allowedUsers"] = [str(user_id)]
            else:
                privacy_result["allowedUsers"] = []

        contact_item.update(privacy_result)

        # Save to database
        self.contact_model.create_contact(contact_item)
        
        # Format response
        return self._format_contact_for_response(contact_item)

    def update_contact(self, contact_id: str, update_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """
        Update an existing contact
        """
        # Get existing contact
        existing_contact = self.contact_model.get_contact_by_id(contact_id)
        if not existing_contact:
            raise Exception("Contact not found")

        # Build update expressions
        update_expressions = []
        expression_values = {}
        expression_names = {}
        
        # Handle regular fields
        for field in UPDATABLE_FIELDS:
            if field in update_data and field not in ["private", "privacy", "allowedUsers"]:
                update_expressions.append(f"#{field} = :{field}")
                expression_values[f":{field}"] = update_data[field]
                expression_names[f"#{field}"] = field

        # Handle privacy settings separately to avoid path conflicts
        privacy_updated = self._handle_privacy_update(
            update_data, existing_contact, user_id, 
            update_expressions, expression_values, expression_names
        )

        # Add audit fields
        update_expressions.append("#updatedAt = :updatedAt")
        update_expressions.append("#updatedBy = :updatedBy")
        update_expressions.append("#updatedByName = :updatedByName")
        expression_values[":updatedAt"] = datetime.utcnow().isoformat()
        expression_values[":updatedBy"] = user_id
        expression_values[":updatedByName"] = get_user_name(user_id)
        expression_names["#updatedAt"] = "updatedAt"
        expression_names["#updatedBy"] = "updatedBy"
        expression_names["#updatedByName"] = "updatedByName"

        if len(update_expressions) <= 3 and not privacy_updated:  # Only audit fields and no privacy changes
            raise Exception("No fields to update")

        # Log the update expressions for debugging
        logger.info(f"Updating contact {contact_id} with expressions: {update_expressions}")
        logger.info(f"Expression values: {expression_values}")
        logger.info(f"Expression names: {expression_names}")

        # Execute update
        try:
            updated_item = self.contact_model.update_contact(
                contact_id, update_expressions, expression_values, expression_names
            )
        except Exception as e:
            logger.error(f"Failed to update contact {contact_id}: {e}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise Exception(f"Failed to update contact: {str(e)}")

        # Format response
        return self._format_contact_metadata(updated_item, user_id)

    def delete_contacts(self, contact_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Delete multiple contacts
        """
        deletion_results = []
        
        for contact_data in contact_data_list:
            contact_id = contact_data["contactID"]
            try:
                # Delete contact and related records
                self.contact_model.delete_contact(contact_id)
                self.contact_model.delete_related_employee_record(contact_id)
                
                deletion_results.append({
                    "contactID": contact_id,
                    "firstName": contact_data.get("firstName", ""),
                    "lastName": contact_data.get("lastName", ""),
                    "displayID": contact_data.get("displayID", ""),
                    "createdBy": contact_data.get("createdBy", ""),
                    "status": "deleted"
                })
                
                logger.info(f"✅ Successfully deleted contact {contact_id}")
                
            except Exception as e:
                logger.error(f"Failed to delete contact {contact_id}: {e}")
                raise Exception(f"Failed to delete contact {contact_id}: {str(e)}")
        
        return deletion_results

    def get_single_contact(self, user_id: str, contact_id: str, include_permissions: bool = False) -> Dict[str, Any]:
        """
        Get a single contact with authorization and privacy checks
        """
        # Check authorization
        if not self.auth_service.can_view_contact(user_id, contact_id):
            error_data = self.auth_service.get_auth_error_details(user_id, "view", contact_id)
            return build_response(status=403, data=error_data)

        # Fetch contact
        contact = self.contact_model.get_contact_by_id(contact_id)
        if not contact:
            return build_response(error="Contact not found", status=404)

        # Apply privacy checks
        if not self.privacy_service.can_access_contact(user_id, contact):
            return build_response(error="Contact not found", status=404)  # Don't reveal it exists but is private

        # Format contact
        formatted_contact = self._format_contact_metadata(contact, user_id if include_permissions else None)

        # Add access method info
        if self.auth_service.is_policy_engine_available():
            access_filter = self.auth_service.get_access_filter(user_id, "Contacts", "view")
            formatted_contact["_accessInfo"] = {
                "accessMethod": access_filter.get("pattern", "unknown"),
                "hasCreatorAccess": "selected_by_creator" in access_filter.get("scopes", []),
                "createdBy": contact.get("createdBy"),
                "isOwnContact": contact.get("createdBy") == user_id
            }

        return build_response(
            data={
                "contact": formatted_contact,
                "accessGranted": True,
                "retrievedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            },
            status=200
        )

    def get_contacts_list(self, user_id: str, event_payload, view_type: str, 
                         include_permissions: bool = False, client_id_filter: str = None) -> Dict[str, Any]:
        """
        Get list of contacts with filtering, authorization, and privacy
        """
        try:
            # Get access filter from policy engine
            access_filter = self.auth_service.get_access_filter(user_id, "Contacts", "view")
            filter_type = access_filter.get("type", "none")
            active_scopes = access_filter.get("scopes", [])
            pattern = access_filter.get("pattern", "unknown")
            
            logger.info(f"Contact list view for user {user_id}: filter_type={filter_type}, pattern={pattern}, scopes={active_scopes}")
            
            # Get contacts based on access pattern
            if filter_type == "all":
                items = self._get_all_contacts(client_id_filter)
            elif filter_type == "all_except_denied":
                items = self._get_all_except_denied_contacts(access_filter, client_id_filter)
            elif filter_type == "specific":
                items = self._get_specific_contacts(access_filter, client_id_filter)
            elif filter_type == "creator_based":
                items = self._get_creator_based_contacts(access_filter, client_id_filter)
            elif filter_type == "mixed":
                items = self._get_mixed_access_contacts(access_filter, client_id_filter)
            else:
                items = []

            # Apply privacy filtering
            filtered_items = self.privacy_service.filter_contacts_by_privacy(items, user_id)
            
            # Format contacts
            formatted_items = []
            for contact in filtered_items:
                try:
                    formatted = self._format_contact_metadata(contact, user_id if include_permissions else None)
                    if formatted:
                        formatted_items.append(formatted)
                except Exception as e:
                    logger.error(f"Error formatting contact: {e}")

            # Build response
            response_data = {
                "contacts": formatted_items,
                "totalCount": len(formatted_items),
                "scope": "+".join(active_scopes) if active_scopes else filter_type,
                "activeScopes": active_scopes,
                "policyEngineAvailable": self.auth_service.is_policy_engine_available(),
                "filterType": filter_type,
                "pattern": pattern,
                "clientFilter": client_id_filter
            }

            # Add debug information
            self._add_debug_info(response_data, access_filter, filter_type, len(items), len(filtered_items))

            return build_response(event=event_payload, data=response_data, status=200)

        except Exception as e:
            logger.error(f"Contacts list view failed: {e}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            return build_response(event=event_payload, error="Internal server error", status=500)

    def get_projects_for_contact(self, contact_id: str) -> List[Dict[str, Any]]:
        """
        Get all projects associated with a contact
        """
        return self.project_model.get_projects_by_contact_id(contact_id)

    # ========= PRIVATE HELPER METHODS =========

    def _handle_privacy_update(self, update_data, existing_contact, user_id, 
                              update_expressions, expression_values, expression_names):
        """Handle privacy settings during contact update"""
        private_setting = update_data.get("private")
        privacy_setting = update_data.get("privacy")
        allowed_users = update_data.get("allowedUsers")
        
        if private_setting is None and privacy_setting is None and allowed_users is None:
            return False  # No privacy changes
        
        privacy_result = self.privacy_service.process_privacy_settings(
            update_data, user_id, is_create=False, existing_contact=existing_contact
        )
        
        # Add privacy fields to update expression
        if "private" in privacy_result:
            update_expressions.append("#privateField = :privateValue")
            expression_values[":privateValue"] = privacy_result["private"]
            expression_names["#privateField"] = "private"

        if "allowedUsers" in privacy_result:
            if privacy_result["allowedUsers"] is None:
                update_expressions.append("REMOVE #allowedUsersField")
                expression_names["#allowedUsersField"] = "allowedUsers"
            else:
                update_expressions.append("#allowedUsersField = :allowedUsersValue")
                expression_values[":allowedUsersValue"] = privacy_result["allowedUsers"]
                expression_names["#allowedUsersField"] = "allowedUsers"
        
        # Clean up old privacy field if needed
        if "privacy" in existing_contact:
            update_expressions.append("REMOVE #privacyField")
            expression_names["#privacyField"] = "privacy"
        
        return True

    def _get_all_contacts(self, client_id_filter=None):
        """Get all contacts"""
        if client_id_filter:
            return self.contact_model.get_contacts_by_client(client_id_filter)
        return self.contact_model.scan_all_contacts()

    def _get_all_except_denied_contacts(self, access_filter, client_id_filter=None):
        """Get all contacts except denied ones"""
        denied_ids = access_filter.get("denied_ids", [])
        all_items = self._get_all_contacts(client_id_filter)
        return [item for item in all_items if item.get("contactID") not in denied_ids]

    def _get_specific_contacts(self, access_filter, client_id_filter=None):
        """Get specific allowed contacts"""
        allowed_ids = access_filter.get("allowed_ids", [])
        if not allowed_ids:
            return []
        
        items = self.contact_model.batch_get_contacts_by_ids(allowed_ids)
        
        if client_id_filter:
            items = [item for item in items if item.get("clientID") == client_id_filter]
        
        return items

    def _get_creator_based_contacts(self, access_filter, client_id_filter=None):
        """Get contacts based on creator access"""
        creator_ids = access_filter.get("creator_ids", [])
        denied_ids = access_filter.get("denied_ids", [])
        
        if not creator_ids:
            return []
        
        items = self.contact_model.get_contacts_by_creators(creator_ids)
        
        if client_id_filter:
            items = [item for item in items if item.get("clientID") == client_id_filter]
        
        if denied_ids:
            items = [item for item in items if item.get("contactID") not in denied_ids]
        
        return items

    def _get_mixed_access_contacts(self, access_filter, client_id_filter=None):
        """Get contacts using mixed access patterns"""
        allowed_ids = access_filter.get("allowed_ids", [])
        creator_ids = access_filter.get("creator_ids", [])
        denied_ids = access_filter.get("denied_ids", [])
        
        items = []
        
        # Get specific contacts
        if allowed_ids:
            specific_items = self.contact_model.batch_get_contacts_by_ids(allowed_ids)
            items.extend(specific_items)
        
        # Get creator-based contacts
        if creator_ids:
            creator_items = self.contact_model.get_contacts_by_creators(creator_ids)
            items.extend(creator_items)
        
        # Remove duplicates
        seen_ids = set()
        unique_items = []
        for item in items:
            contact_id = item.get("contactID")
            if contact_id and contact_id not in seen_ids:
                seen_ids.add(contact_id)
                unique_items.append(item)
        
        items = unique_items
        
        # Apply filters
        if client_id_filter:
            items = [item for item in items if item.get("clientID") == client_id_filter]
        
        if denied_ids:
            items = [item for item in items if item.get("contactID") not in denied_ids]
        
        return items

    def _format_contact_metadata(self, contact: Dict[str, Any], user_id: str = None) -> Dict[str, Any]:
        """Format contact with metadata and permissions"""
        if not contact or not isinstance(contact, dict):
            logger.warning(f"Invalid contact data: {type(contact)}")
            return None

        # Start with all original contact data
        formatted_contact = contact.copy()

        # Format dates
        if "createdAt" in formatted_contact:
            formatted_contact["createdAt"] = format_date(contact.get("createdAt", ""))
        if "updatedAt" in formatted_contact:
            formatted_contact["updatedAt"] = format_date(contact.get("updatedAt", ""))

        # Add human-readable names
        self._add_user_names(formatted_contact, contact)
        self._add_client_name(formatted_contact, contact)

        # Add permission metadata if requested
        if user_id and self.auth_service.is_policy_engine_available():
            self._add_permissions_metadata(formatted_contact, contact, user_id)

        return formatted_contact

    def _add_user_names(self, formatted_contact, contact):
        """Add user names to formatted contact"""
        created_by = contact.get("createdBy")
        if created_by:
            try:
                formatted_contact["createdByName"] = get_username(created_by)
            except Exception as e:
                logger.warning(f"Error getting creator name for {created_by}: {e}")
                formatted_contact["createdByName"] = "Unknown"

        updated_by = contact.get("updatedBy")
        if updated_by:
            try:
                formatted_contact["updatedByName"] = get_username(updated_by)
            except Exception as e:
                logger.warning(f"Error getting updater name for {updated_by}: {e}")
                formatted_contact["updatedByName"] = "Unknown"

    def _add_client_name(self, formatted_contact, contact):
        """Add client name to formatted contact"""
        client_id = contact.get("clientID")
        if client_id:
            try:
                formatted_contact["clientName"] = get_client_name(client_id)
            except Exception as e:
                logger.warning(f"Error getting client name for {client_id}: {e}")
                formatted_contact["clientName"] = "Unknown Client"

    def _add_permissions_metadata(self, formatted_contact, contact, user_id):
        """Add permissions metadata to formatted contact"""
        contact_id = contact.get("contactID")
        if contact_id:
            try:
                formatted_contact["_permissions"] = {
                    "canEdit": self.auth_service.can_modify_contact(user_id, contact_id),
                    "canDelete": self.auth_service.can_delete_contact(user_id, contact_id),
                    "canView": True,  # Already confirmed by being in the list
                    "isOwner": contact.get("createdBy") == user_id
                }
            except Exception as e:
                logger.warning(f"Error adding permissions metadata for contact {contact_id}: {e}")

    def _format_contact_for_response(self, contact_item):
        """Format contact for creation response"""
        return {
            "contactID": contact_item["contactID"],
            "displayID": contact_item["displayID"],
            "firstName": contact_item["firstName"],
            "lastName": contact_item["lastName"],
            "officialEmail": contact_item["officialEmail"],
            "clientID": contact_item["clientID"],
            "status": contact_item["status"],
            "createdByName": contact_item["createdByName"],
            "updatedByName": contact_item["updatedByName"],
            "createdAt": contact_item["createdAt"],
            "createdBy": contact_item["createdBy"],
            "private": contact_item.get("private", False),
            "allowedUsers": contact_item.get("allowedUsers", []) if contact_item.get("private", False) else []
        }

    def _add_debug_info(self, response_data, access_filter, filter_type, raw_count, filtered_count):
        """Add debug information to response"""
        if filter_type == "all_except_denied":
            response_data["debug"] = {
                "deniedCount": len(access_filter.get("denied_ids", [])),
                "message": f"Showing all contacts except {len(access_filter.get('denied_ids', []))} denied ones",
                "rawItemsCount": raw_count,
                "filteredItemsCount": filtered_count
            }
        elif filter_type == "specific" and not response_data["contacts"]:
            response_data["debug"] = {
                "allowedIdsCount": len(access_filter.get("allowed_ids", [])),
                "deniedIdsCount": len(access_filter.get("denied_ids", [])),
                "message": "No items returned from batch get operation"
            }
        elif filter_type in ["creator_based", "mixed"]:
            response_data["debug"] = {
                "creatorCount": len(access_filter.get("creator_ids", [])),
                "accessMethod": filter_type,
                "message": f"Access granted via {filter_type} pattern"
            }

logger.info("✅ ContactService initialized")