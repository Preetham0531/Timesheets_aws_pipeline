"""
Client Business Logic Service
Handles all client-related business operations and workflows.
"""

import uuid
import json
import logging
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from models.client_model import ClientModel
from models.project_model import ProjectModel
from services.policy_service import PolicyService
from utils import (
    build_response, get_username, format_date, generate_unique_display_id
)

logger = logging.getLogger("client_service")

class ClientService:
    def __init__(self):
        self.client_model = ClientModel()
        self.project_model = ProjectModel()
        self.policy_service = PolicyService()

    def create_client(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new client with comprehensive validation and policy checks"""
        body, error_resp = self._validate_json_body(event_payload)
        if error_resp:
            return error_resp

        user_id = authenticated_user["user_id"]
        username = get_username(user_id)

        # Authorization check
        if not self.policy_service.can_create_client(user_id):
            return self._build_authorization_error(event_payload, "create", user_id)

        # Validate required fields
        validation_error = self._validate_create_fields(body)
        if validation_error:
            return validation_error

        company_name = body.get("companyName").strip()
        email = body.get("email").strip()

        # Check for duplicate company name
        if self.client_model.check_duplicate_company_name(company_name):
            return build_response(
                event=event_payload,
                error="Validation error: Company name already in use",
                status=400,
            )

        # Generate unique IDs and timestamp
        current_time = datetime.utcnow().isoformat()
        client_id = str(uuid.uuid4())

        try:
            display_id = generate_unique_display_id("CLI")
        except Exception as e:
            logger.error(f"Display ID generation failed: {e}")
            return build_response(
                event=event_payload,
                error=f"ID generation failed: {str(e)}",
                status=500,
            )

        # Handle privacy settings (creator auto-added if private; allowedUsers not mandatory)
        is_private, allowed_users, privacy_error = self._process_privacy_settings(body, creator_user_id=user_id)
        if privacy_error:
            return privacy_error

        # Build client record
        client_record = self._build_client_record(
            client_id, display_id, body, current_time, user_id, username,
            is_private, allowed_users
        )

        # Save to database
        try:
            self.client_model.create_client(client_record)
            logger.info(f"✅ Created client {client_id} ({company_name}) by user {user_id}")

            return build_response(
                event=event_payload,
                data={
                    "message": "Client created successfully",
                    "client": self._format_client_response(client_record, username)
                },
                status=201,
            )
        except Exception as e:
            logger.error(f"Failed to create client: {e}")
            return self._handle_error(event_payload, e, "client_creation_failed")

    def get_clients(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve clients with comprehensive filtering and permissions"""
        user_id = authenticated_user["user_id"]
        qs = event_payload.get("queryStringParameters") or {}

        client_id = qs.get("clientID")
        view_type = qs.get("view", "full")
        include_permissions = qs.get("includePermissions", "").lower() == "true"
        include_projects = qs.get("includeProjects", "").lower() == "true"
        projects_only = qs.get("projectsOnly", "").lower() == "true"
        debug_mode = qs.get("debug", "").lower() == "true"

        logger.info(f"Client GET request: user={user_id}, view={view_type}, clientID={client_id}")

        # Handle debug endpoint
        if debug_mode:
            return self.policy_service.get_debug_info(user_id, event_payload, include_projects or projects_only)

        try:
            if client_id:
                if projects_only:
                    return self._handle_client_projects_only(user_id, client_id, event_payload, include_permissions)
                elif include_projects:
                    return self._handle_client_with_projects(user_id, client_id, event_payload, include_permissions)
                else:
                    return self._handle_specific_client_view(user_id, client_id, event_payload, include_permissions)
            else:
                return self._handle_clients_list_view(user_id, event_payload, view_type, include_permissions)

        except Exception as e:
            logger.error(f"GET request failed for user {user_id}: {e}")
            return self._handle_error(event_payload, e, "get_clients_failed")

    def update_client(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing client with comprehensive validation"""
        body, error_resp = self._validate_json_body(event_payload)
        if error_resp:
            return error_resp

        user_id = authenticated_user["user_id"]
        client_id = body.get("clientID")

        if not client_id:
            return build_response(
                event=event_payload,
                error="Validation error: clientID is required",
                status=400,
            )

        # Fetch and authorize
        existing_client = self.client_model.get_client_by_id(client_id)
        if not existing_client:
            return build_response(event=event_payload, error="Client not found", status=404)

        if not self.policy_service.can_modify_client(user_id, client_id):
            return self._build_authorization_error(event_payload, "modify", user_id, client_id, existing_client)

        # Validate duplicate company name if being changed
        new_company_name = body.get("companyName")
        if new_company_name and new_company_name != existing_client.get("companyName"):
            if self.client_model.check_duplicate_company_name(new_company_name, client_id):
                return build_response(
                    event=event_payload,
                    error="Validation error: company name already in use",
                    status=400,
                )

        # Build update data (ensure default allowedUsers when toggling to private without a list)
        update_data = self._build_update_data(body, user_id, existing_client)

        if not update_data["expressions"]:
            return build_response(event=event_payload, error="No fields to update", status=400)

        # Execute update
        try:
            updated_item = self.client_model.update_client(client_id, update_data)
            logger.info(f"✅ Updated client {client_id} by user {user_id}")

            formatted_client = self._format_client_metadata(updated_item, user_id)

            return build_response(
                event=event_payload,
                data={
                    "message": "Client updated successfully",
                    "client": formatted_client,
                    "updatedFields": [field for field in body.keys() if field != "clientID"]
                },
                status=200
            )
        except Exception as e:
            logger.error(f"Update failed for client {client_id}: {e}")
            return self._handle_error(event_payload, e, "update_client_failed")

    def delete_clients(self, event_payload: Dict[str, Any], authenticated_user: Dict[str, Any]) -> Dict[str, Any]:
        """Delete one or more clients with authorization checks"""
        body, error_resp = self._validate_json_body(event_payload)
        if error_resp:
            return error_resp

        user_id = authenticated_user["user_id"]

        # Support both single and batch delete
        client_ids = body.get("clientIDs")
        if not client_ids:
            single_id = body.get("clientID")
            if single_id:
                client_ids = [single_id]

        if not client_ids or not isinstance(client_ids, list):
            return build_response(
                event=event_payload,
                error="Validation error: clientIDs must be a non-empty list",
                status=400
            )

        logger.info(f"Delete request for {len(client_ids)} clients by user {user_id}")

        # Validate authorization for all clients
        try:
            missing, denied, valid_clients = self._validate_delete_authorization(user_id, client_ids)
        except Exception as e:
            logger.error(f"Error during delete validation: {e}")
            return build_response(
                event=event_payload,
                status=500,
                data={"error": "Authorization validation error", "details": str(e)}
            )

        if missing:
            return build_response(
                event=event_payload,
                error=f"Validation error: clientIDs not found: {', '.join(missing)}",
                status=400,
            )

        if denied:
            return self._build_delete_authorization_error(event_payload, denied, user_id)

        # Perform deletions
        deletion_results = []
        for client_data in valid_clients:
            client_id = client_data["clientID"]
            try:
                self.client_model.delete_client(client_id)
                deletion_results.append({
                    "clientID": client_id,
                    "companyName": client_data.get("companyName", ""),
                    "displayID": client_data.get("displayID", ""),
                    "status": "deleted"
                })
                logger.info(f"✅ Successfully deleted client {client_id}")
            except Exception as e:
                logger.error(f"Failed to delete client {client_id}: {e}")
                return self._handle_error(event_payload, e, f"delete_client_{client_id}_failed")

        return build_response(
            event=event_payload,
            data={
                "message": "Client(s) deleted successfully",
                "deletedCount": len(client_ids),
                "deletionResults": deletion_results,
                "timestamp": datetime.utcnow().isoformat()
            },
            status=200
        )

    # Private helper methods
    def _validate_json_body(self, event) -> Tuple[dict, Optional[dict]]:
        """Parse and validate JSON body"""
        try:
            body = json.loads(event.get("body", "{}")) or {}
            return body, None
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return {}, build_response(event=event, error="Invalid JSON in request body", status=400)

    def _validate_create_fields(self, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate required fields for client creation"""
        company_name = (body.get("companyName") or "").strip()
        email = (body.get("email") or "").strip()
        phone = (body.get("phone") or "").strip()

        missing_fields = []
        if not company_name:
            missing_fields.append("companyName")
        if not email:
            missing_fields.append("email")
        if not phone:
            missing_fields.append("phone")

        if missing_fields:
            return build_response(
                error=f"Validation error: Required fields missing: {', '.join(missing_fields)}",
                status=400,
            )

        # Email format validation
        if "@" not in email or "." not in email.split("@")[1]:
            return build_response(
                error="Validation error: Invalid email format",
                status=400,
            )

        return None

    def _process_privacy_settings(self, body: Dict[str, Any], creator_user_id: str) -> Tuple[bool, List[str], Optional[Dict[str, Any]]]:
        """
        Process privacy settings from request body.

        Rules:
        - If private is True:
          - allowedUsers is OPTIONAL.
          - Ensure the creator_user_id is present in allowedUsers (auto-add if missing).
        - If private is False or omitted:
          - allowedUsers = [].
        """
        is_private = bool(body.get("private", False))
        raw_allowed = body.get("allowedUsers", None)

        if not is_private:
            # Public client: ignore any provided allowedUsers
            logger.info("Creating public client (default behavior)")
            return False, [], None

        # Private client: allowedUsers may be omitted
        if raw_allowed is None:
            allowed_users: List[str] = [str(creator_user_id)]
        else:
            if not isinstance(raw_allowed, list):
                return False, [], build_response(
                    error="Validation error: allowedUsers must be a list when provided",
                    status=400,
                )
            # Normalize, dedupe, and ensure creator is present
            norm = [str(uid).strip() for uid in raw_allowed if str(uid).strip()]
            if str(creator_user_id) not in norm:
                norm.append(str(creator_user_id))
            allowed_users = sorted(set(norm))

        logger.info(f"Creating private client with {len(allowed_users)} allowed users (creator enforced)")
        return True, allowed_users, None

    def _build_client_record(self, client_id: str, display_id: str, body: Dict[str, Any],
                           current_time: str, user_id: str, username: str,
                           is_private: bool, allowed_users: List[str]) -> Dict[str, Any]:
        """Build client record for database insertion"""
        return {
            "clientID": client_id,
            "displayID": display_id,
            "companyName": body.get("companyName").strip(),
            "email": body.get("email").strip(),
            "phone": body.get("phone").strip(),
            "status": body.get("status", "Active"),
            "website": body.get("website", ""),
            "address": self._normalize_address(body.get("address", {})),
            "createdAt": current_time,
            "updatedAt": current_time,
            "createdBy": user_id,
            "createdByName": username,
            "updatedByName": username,
            "updatedBy": user_id,
            "private": is_private,
            "allowedUsers": allowed_users
        }

    def _normalize_address(self, address_data: dict) -> dict:
        """Normalize address object with default values"""
        return {
            "street1": address_data.get("street1", ""),
            "street2": address_data.get("street2", ""),
            "city": address_data.get("city", ""),
            "state": address_data.get("state", ""),
            "country": address_data.get("country", ""),
            "zipCode": address_data.get("zipCode", ""),
        }

    def _format_client_response(self, client_record: Dict[str, Any], username: str) -> Dict[str, Any]:
        """Format client record for API response"""
        return {
            "clientID": client_record["clientID"],
            "displayID": client_record["displayID"],
            "companyName": client_record["companyName"],
            "email": client_record["email"],
            "phone": client_record["phone"],
            "status": client_record["status"],
            "website": client_record["website"],
            "createdAt": client_record["createdAt"],
            "createdBy": client_record["createdBy"],
            "createdByName": username,
            "private": client_record["private"],
            "allowedUsers": client_record["allowedUsers"]
        }

    def _build_authorization_error(self, event_payload: Dict[str, Any], action: str, user_id: str,
                                 client_id: str = None, existing_client: Dict[str, Any] = None) -> Dict[str, Any]:
        """Build detailed authorization error response"""
        return self.policy_service.build_authorization_error(
            event_payload, action, user_id, client_id, existing_client
        )

    def _build_delete_authorization_error(self, event_payload: Dict[str, Any], denied: List[str], user_id: str) -> Dict[str, Any]:
        """Build authorization error for delete operations"""
        return self.policy_service.build_delete_authorization_error(event_payload, denied, user_id)

    def _handle_error(self, event_payload: Dict[str, Any], exc: Exception, code: str, status: int = 500) -> Dict[str, Any]:
        """Standardized error handler with logging"""
        logger.error("%s: %s\n%s", code, exc, traceback.format_exc())
        return build_response(event=event_payload, error="Internal server error", status=status)

    def _handle_clients_list_view(self, user_id: str, event_payload: Dict[str, Any],
                                view_type: str, include_permissions: bool = False) -> Dict[str, Any]:
        """Handle clients list view with filtering and permissions"""
        # Get access filter from policy service
        access_filter = self.policy_service.get_accessible_records_filter(user_id, "view")

        # Get clients based on filter
        items = self.client_model.get_clients_by_filter(access_filter)

        # Apply privacy filtering
        items = self._apply_privacy_filter(user_id, items)

        # Format items
        formatted_items = [self._format_client_metadata(c, user_id if include_permissions else None) for c in items]

        return self.policy_service.build_list_response(
            event_payload, formatted_items, access_filter, view_type
        )

    def _handle_specific_client_view(self, user_id: str, client_id: str,
                                   event_payload: Dict[str, Any], include_permissions: bool = False) -> Dict[str, Any]:
        """Handle single client retrieval"""
        # Check authorization
        if not self.policy_service.can_view_client(user_id, client_id):
            return self._build_authorization_error(event_payload, "view", user_id, client_id)

        # Fetch client
        client = self.client_model.get_client_by_id(client_id)
        if not client:
            return build_response(event=event_payload, error="Client not found", status=404)

        # Apply privacy filtering
        if not self._can_access_private_client(user_id, client):
            return build_response(
                event=event_payload,
                status=403,
                data={
                    "error": "Not authorized to view this client",
                    "clientID": client_id,
                    "reason": "privacy_restriction"
                }
            )

        # Format response
        formatted_client = self._format_client_metadata(client, user_id if include_permissions else None)

        return build_response(
            event=event_payload,
            data={
                "client": formatted_client,
                "accessGranted": True,
                "retrievedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            },
            status=200
        )

    def _handle_client_projects_only(self, user_id: str, client_id: str,
                                    event_payload: Dict[str, Any], include_permissions: bool) -> Dict[str, Any]:
        """Get only projects for a specific client"""
        # Check client access
        if not self.policy_service.can_view_client(user_id, client_id):
            return build_response(event=event_payload, error=f"Not authorized to view client {client_id}", status=403)

        # Check projects access
        if not self.policy_service.can_view_projects(user_id):
            return build_response(event=event_payload, error="Not authorized to view projects", status=403)

        # Get client info
        client_info = self.client_model.get_client_by_id(client_id)
        if not client_info:
            return build_response(event=event_payload, error=f"Client {client_id} not found", status=404)

        # Get projects
        projects = self.project_model.get_client_projects_with_policy(user_id, client_id)

        return build_response(
            event=event_payload,
            data={
                "clientID": client_id,
                "clientName": client_info.get("companyName", "Unknown"),
                "projects": projects,
                "projectsCount": len(projects),
                "retrievedAt": datetime.utcnow().isoformat() + "Z",
                "retrievedBy": user_id
            },
            status=200
        )

    def _handle_client_with_projects(self, user_id: str, client_id: str,
                                    event_payload: Dict[str, Any], include_permissions: bool) -> Dict[str, Any]:
        """Get client details along with their projects"""
        # Get client details first
        client_response = self._handle_specific_client_view(user_id, client_id, event_payload, include_permissions)

        if client_response.get("statusCode") != 200:
            return client_response

        # Parse and enhance with projects
        client_data = json.loads(client_response.get("body", "{}"))

        if self.policy_service.can_view_projects(user_id):
            try:
                projects = self.project_model.get_client_projects_with_policy(user_id, client_id)
                client_data["projects"] = projects
                client_data["projectsCount"] = len(projects)
            except Exception as e:
                logger.warning(f"Error adding projects to client {client_id}: {e}")
                client_data["projects"] = []
                client_data["projectsCount"] = 0
        else:
            client_data["projects"] = []
            client_data["projectsCount"] = 0
            client_data["projectsAccessDenied"] = True

        return build_response(event=event_payload, data=client_data, status=200)

    def _build_update_data(self, body: Dict[str, Any], user_id: str, existing_client: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build update data structure for client updates"""
        update_expressions = []
        expression_values = {}
        expression_names = {}

        # Handle updatable fields
        updatable_fields = {
            "companyName": "companyName",
            "email": "email",
            "phone": "phone",
            "category": "category",
            "website": "website",
            "status": "status"
        }

        for input_field, db_field in updatable_fields.items():
            if input_field in body:
                if db_field == "status":
                    update_expressions.append("#status = :status")
                    expression_values[":status"] = body[input_field]
                    expression_names["#status"] = "status"
                else:
                    update_expressions.append(f"{db_field} = :{db_field}")
                    expression_values[f":{db_field}"] = body[input_field]

        # Handle address
        if "address" in body and isinstance(body["address"], dict):
            update_expressions.append("address = :address")
            expression_values[":address"] = self._normalize_address(body["address"])

        # Handle privacy fields
        if "private" in body:
            is_private = bool(body["private"])
            update_expressions.append("private = :private")
            expression_values[":private"] = is_private

            if is_private:
                if "allowedUsers" in body:
                    allowed_users = body.get("allowedUsers", [])
                    if not isinstance(allowed_users, list):
                        raise ValueError("allowedUsers must be a list when client is private")
                    # normalize + dedupe
                    allowed_users = sorted(set(str(uid).strip() for uid in allowed_users if str(uid).strip()))
                    update_expressions.append("allowedUsers = :allowedUsers")
                    expression_values[":allowedUsers"] = allowed_users
                else:
                    # Default to creator if toggled to private without providing a list
                    creator_id = (existing_client or {}).get("createdBy") or user_id
                    update_expressions.append("allowedUsers = :allowedUsers")
                    expression_values[":allowedUsers"] = [str(creator_id)]
            else:
                # Public → always clear allowedUsers
                update_expressions.append("allowedUsers = :allowedUsers")
                expression_values[":allowedUsers"] = []
        elif "allowedUsers" in body:
            allowed_users = body.get("allowedUsers", [])
            if not isinstance(allowed_users, list):
                raise ValueError("allowedUsers must be a list")
            allowed_users = sorted(set(str(uid).strip() for uid in allowed_users if str(uid).strip()))
            update_expressions.append("allowedUsers = :allowedUsers")
            expression_values[":allowedUsers"] = allowed_users

        # Add audit fields
        update_expressions.extend([
            "updatedAt = :updatedAt",
            "updatedBy = :updatedBy",
            "updatedByName = :updatedByName"
        ])
        expression_values[":updatedAt"] = datetime.utcnow().isoformat()
        expression_values[":updatedBy"] = user_id
        expression_values[":updatedByName"] = get_username(user_id)

        return {
            "expressions": update_expressions,
            "values": expression_values,
            "names": expression_names
        }

    def _validate_delete_authorization(self, user_id: str, client_ids: List[str]) -> Tuple[List[str], List[str], List[dict]]:
        """Validate authorization for batch delete operations"""
        missing = []
        denied = []
        valid_clients = []

        for client_id in client_ids:
            try:
                item = self.client_model.get_client_by_id(client_id)
                if not item:
                    missing.append(client_id)
                    continue

                if self.policy_service.can_delete_client(user_id, client_id):
                    valid_clients.append(item)
                else:
                    denied.append(client_id)

            except Exception as e:
                logger.error(f"Error validating client {client_id}: {e}")
                denied.append(client_id)

        return missing, denied, valid_clients

    def _apply_privacy_filter(self, user_id: str, clients: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply privacy filtering to a list of clients"""
        if not clients:
            return []

        accessible_clients = []
        for client in clients:
            if self._can_access_private_client(user_id, client):
                accessible_clients.append(client)

        return accessible_clients

    def _can_access_private_client(self, user_id: str, client: Dict[str, Any]) -> bool:
        """Check if user can access a private client"""
        is_private = client.get("private", False)
        if not is_private:
            return True

        allowed_users = client.get("allowedUsers", [])
        if not isinstance(allowed_users, list):
            allowed_users = []

        return str(user_id) in set(str(uid) for uid in allowed_users)

    def _format_client_metadata(self, client: Dict[str, Any], user_id: str = None) -> Dict[str, Any]:
        """Add formatted metadata to client record"""
        formatted_client = client.copy()

        formatted_client["createdAt"] = format_date(client.get("createdAt", ""))
        formatted_client["updatedAt"] = format_date(client.get("updatedAt", ""))
        formatted_client["createdByName"] = client.get("createdByName", "")
        formatted_client["updatedByName"] = client.get("updatedByName", "")

        # Add permission metadata if user context provided
        if user_id:
            client_id = client.get("clientID")
            if client_id:
                try:
                    formatted_client["_permissions"] = {
                        "canEdit": self.policy_service.can_modify_client(user_id, client_id),
                        "canDelete": self.policy_service.can_delete_client(user_id, client_id),
                        "canView": True,
                        "isOwner": client.get("createdBy") == user_id
                    }
                except Exception as e:
                    logger.warning(f"Error adding permissions metadata for client {client_id}: {e}")

        return formatted_client
