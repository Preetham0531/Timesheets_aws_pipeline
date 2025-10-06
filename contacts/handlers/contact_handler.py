import json
import logging
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from services.contact_service import ContactService
from services.authorization_service import AuthorizationService
from services.privacy_service import PrivacyService
from models.contact_model import ContactModel
from utils import build_response

# ========= LOGGING =========
logger = logging.getLogger("contact_handler")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class ContactHandler:
    """
    Handler for contact-related requests.
    Parses input, validates requests, and delegates to appropriate services.
    """
    
    def __init__(self):
        self.contact_service = ContactService()
        self.auth_service = AuthorizationService()
        self.privacy_service = PrivacyService()
        self.contact_model = ContactModel()

    def handle_create_contact(self, event, body, user_id, user_role):
        """Handle contact creation requests"""
        try:
            # Validate authorization
            if not self.auth_service.can_create_contact(user_id):
                return self._build_auth_error_response(event, user_id, "create")
            
            # Parse and validate input
            validation_result = self._validate_create_input(body)
            if validation_result["error"]:
                return build_response(
                    event=event,
                    error=validation_result["error"],
                    status=400
                )
            
            # Check client access
            client_id = body["clientID"]
            if not self.auth_service.can_access_client(user_id, client_id):
                return build_response(
                    event=event,
                    error="Not authorized to create contacts for this client",
                    status=403
                )
            
            # Check for duplicate email
            if self.contact_model.email_exists_for_client(body["officialEmail"], client_id):
                return build_response(
                    event=event,
                    error="Validation error: officialEmail already exists for this client",
                    status=400
                )
            
            # Create contact
            contact = self.contact_service.create_contact(body, user_id)
            
            logger.info(f"✅ Created contact {contact['contactID']} by user {user_id}")
            
            return build_response(
                event=event,
                data={
                    "message": "Contact created successfully",
                    "contact": contact
                },
                status=201
            )
            
        except Exception as e:
            logger.error(f"Failed to create contact: {e}")
            return self._handle_error(event, e, "contact_creation_failed")

    def handle_get_contacts(self, event, user_id, user_role):
        """Handle contact retrieval requests"""
        try:
            query_params = event.get("queryStringParameters") or {}
            
            contact_id = query_params.get("contactID")
            client_id_filter = query_params.get("clientID")
            view_type = query_params.get("view", "full")
            include_permissions = query_params.get("includePermissions", "").lower() == "true"
            debug_mode = query_params.get("debug", "").lower() == "true"
            
            logger.info(f"Contact GET request: user={user_id}, view={view_type}, contactID={contact_id}, clientFilter={client_id_filter}, debug={debug_mode}")
            
            # Handle debug endpoint
            if debug_mode:
                return self._handle_debug_request(event, user_id)
            
            # Handle single contact request
            if contact_id:
                return self._handle_single_contact_request(event, contact_id, user_id, include_permissions)
            
            # Handle contact list request
            return self._handle_contact_list_request(event, user_id, view_type, include_permissions, client_id_filter)
            
        except Exception as e:
            logger.error(f"GET request failed for user {user_id}: {e}")
            return self._handle_error(event, e, "get_contacts_failed")

    def handle_update_contact(self, event, body, user_id, user_role):
        """Handle contact update requests"""
        try:
            contact_id = body.get("contactID")
            if not contact_id:
                return build_response(
                    event=event,
                    error="Validation error: contactID is required",
                    status=400
                )
            
            # Check if contact exists and user can modify it
            if not self.auth_service.can_modify_contact(user_id, contact_id):
                return self._build_auth_error_response(event, user_id, "modify", contact_id)
            
            # Get existing contact
            existing_contact = self.contact_model.get_contact_by_id(contact_id)
            if not existing_contact:
                return build_response(event=event, error="Contact not found", status=404)
            
            # Validate update
            validation_result = self._validate_update_input(body, existing_contact, user_id)
            if validation_result["error"]:
                return build_response(
                    event=event,
                    error=validation_result["error"],
                    status=validation_result["status"]
                )
            
            # Update contact
            updated_contact = self.contact_service.update_contact(contact_id, body, user_id)
            
            logger.info(f"✅ Updated contact {contact_id} by user {user_id}")
            
            return build_response(
                event=event,
                data={
                    "message": "Contact updated successfully",
                    "contact": updated_contact,
                    "updatedFields": [field for field in body.keys() if field != "contactID"]
                },
                status=200
            )
            
        except Exception as e:
            logger.error(f"Update failed for contact {body.get('contactID')}: {e}")
            return self._handle_error(event, e, "update_contact_failed")

    def handle_delete_contact(self, event, body, user_id, user_role):
        """Handle contact deletion requests"""
        try:
            # Support both single and batch delete
            contact_ids = body.get("contactIDs")
            if not contact_ids:
                single_id = body.get("contactID")
                if single_id:
                    contact_ids = [single_id]
            
            if not contact_ids or not isinstance(contact_ids, list):
                return build_response(
                    event=event,
                    error="Validation error: contactIDs must be a non-empty list",
                    status=400
                )
            
            logger.info(f"Delete request for {len(contact_ids)} contacts by user {user_id}")
            
            # Validate deletion permissions
            validation_result = self.auth_service.validate_batch_delete(user_id, contact_ids)
            if validation_result["missing"] or validation_result["denied"]:
                return self._build_delete_error_response(event, validation_result, user_id)
            
            # Perform deletions
            deletion_results = self.contact_service.delete_contacts(validation_result["valid_contacts"])
            
            return build_response(
                event=event,
                data={
                    "message": "Contact(s) deleted successfully",
                    "deletedCount": len(contact_ids),
                    "deletionResults": deletion_results,
                    "timestamp": datetime.utcnow().isoformat()
                },
                status=200
            )
            
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return self._handle_error(event, e, "delete_contact_failed")

    def handle_permissions_test(self, event, user_context):
        """Handle permissions testing endpoint"""
        try:
            qs = event.get("queryStringParameters") or {}
            user_id = user_context["user_id"]
            
            test_user_id = qs.get("testUserId", user_id)
            contact_id = qs.get("contactID")
            
            if contact_id:
                test_results = self.auth_service.test_contact_permissions(test_user_id, contact_id)
            else:
                test_results = self.auth_service.get_permissions_summary(test_user_id)
            
            return build_response(
                event=event,
                data={
                    "testResults": test_results,
                    "currentUser": user_id,
                    "testUser": test_user_id
                },
                status=200
            )
            
        except Exception as e:
            logger.error(f"Permissions test failed: {e}")
            return self._handle_error(event, e, "permissions_test_failed")

    def handle_get_users_for_privacy(self, event, user_id, user_role):
        """Handle users for privacy selection endpoint"""
        try:
            query_params = event.get("queryStringParameters") or {}
            search_query = query_params.get("search", "").strip().lower()
            limit = min(int(query_params.get("limit", "50")), 100)
            
            logger.info(f"Getting users for privacy selection: user={user_id}, search='{search_query}', limit={limit}")
            
            # Check if user can view users
            if not self.auth_service.can_view_users(user_id):
                return build_response(
                    event=event,
                    error="Not authorized to view users",
                    status=403
                )
            
            # Get users
            users = self.privacy_service.get_users_for_privacy(search_query, limit)
            
            return build_response(
                event=event,
                data={
                    "users": users,
                    "totalCount": len(users),
                    "searchQuery": search_query,
                    "limit": limit,
                    "requestedBy": user_id
                },
                status=200
            )
            
        except Exception as e:
            logger.error(f"Get users for privacy failed: {e}")
            return self._handle_error(event, e, "get_users_for_privacy_failed")

    # ========= PRIVATE HELPER METHODS =========
    
    def _validate_create_input(self, body):
        """Validate contact creation input"""
        first_name = (body.get("firstName") or "").strip()
        official_email = (body.get("officialEmail") or "").strip()
        client_id = body.get("clientID")
        
        missing_fields = []
        if not first_name:
            missing_fields.append("firstName")
        if not official_email:
            missing_fields.append("officialEmail")
        if not client_id:
            missing_fields.append("clientID")
        
        if missing_fields:
            return {
                "error": f"Validation error: Required fields missing: {', '.join(missing_fields)}",
                "status": 400
            }
        
        return {"error": None}

    def _validate_update_input(self, body, existing_contact, user_id):
        """Validate contact update input"""
        # Client change validation
        new_client_id = body.get("clientID")
        current_client_id = existing_contact.get("clientID")
        
        if new_client_id and new_client_id != current_client_id:
            if not self.auth_service.can_access_client(user_id, new_client_id):
                return {
                    "error": "Not authorized to assign contact to this client",
                    "status": 403
                }
        
        # Email duplication check
        new_email = body.get("officialEmail")
        if new_email and new_email != existing_contact.get("officialEmail"):
            effective_client_id = new_client_id or current_client_id
            if self.contact_model.email_exists_for_client(new_email, effective_client_id, existing_contact["contactID"]):
                return {
                    "error": "Validation error: officialEmail already exists for this client",
                    "status": 400
                }
        
        return {"error": None}

    def _handle_single_contact_request(self, event, contact_id, user_id, include_permissions):
        """Handle single contact retrieval"""
        contact_response = self.contact_service.get_single_contact(user_id, contact_id, include_permissions)
        
        # Add projects to the response
        if isinstance(contact_response, dict) and contact_response.get("statusCode") == 200:
            try:
                projects = self.contact_service.get_projects_for_contact(contact_id)
                body_data = json.loads(contact_response["body"])
                body_data["projects"] = projects
                body_data["projectCount"] = len(projects)
                contact_response["body"] = json.dumps(body_data)
            except Exception as e:
                logger.error(f"Error adding projects to contact response: {e}")
        
        return contact_response

    def _handle_contact_list_request(self, event, user_id, view_type, include_permissions, client_id_filter):
        """Handle contact list retrieval"""
        return self.contact_service.get_contacts_list(
            user_id, event, view_type, include_permissions, client_id_filter
        )

    def _handle_debug_request(self, event, user_id):
        """Handle debug permissions request"""
        debug_info = self.auth_service.get_permissions_debug(user_id)
        return build_response(
            event=event,
            data={"debugInfo": debug_info},
            status=200
        )

    def _build_auth_error_response(self, event, user_id, action, contact_id=None):
        """Build authorization error response"""
        error_data = self.auth_service.get_auth_error_details(user_id, action, contact_id)
        return build_response(event=event, status=403, data=error_data)

    def _build_delete_error_response(self, event, validation_result, user_id):
        """Build delete validation error response"""
        if validation_result["missing"]:
            return build_response(
                event=event,
                error=f"Validation error: contactIDs not found: {', '.join(validation_result['missing'])}",
                status=400
            )
        
        if validation_result["denied"]:
            error_data = self.auth_service.get_delete_auth_error_details(user_id, validation_result["denied"])
            return build_response(event=event, status=403, data=error_data)

    def _handle_error(self, event, exception, error_code):
        """Handle generic errors with logging"""
        logger.error(f"{error_code}: {exception}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        return build_response(event=event, error="Internal server error", status=500)

logger.info("✅ ContactHandler initialized")