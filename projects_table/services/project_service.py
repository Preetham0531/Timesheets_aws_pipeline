# -------------------- PROJECT BUSINESS LOGIC SERVICE --------------------
import json
import uuid
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from boto3.dynamodb.conditions import Attr, Key

from models.database_models import (
    PROJECTS_TABLE, CLIENTS_TABLE, CONTACTS_TABLE, ASSIGNMENTS_TABLE, SEQUENCES_TABLE
)
from models.user_lookups import get_username, get_user_name, get_client_name, get_contact_name
from models.validation_models import validate_contact_and_client
from utils.id_generators import generate_unique_display_id
from utils.date_helpers import format_date
from utils.logging_helpers import get_logger
from services.policy_service import policy_service

# Initialize logger
logger = get_logger(__name__)

# Constants
BATCH_SIZE = 100
DEFAULT_PAGE_SIZE = 50
UPDATABLE_FIELDS = [
    "clientID", "projectName", "description", "startDate", "endDate", 
    "tasks", "status", "contactID", "private", "allowedUsers"
]

class ProjectService:
    """Service class for project business logic"""
    
    @staticmethod
    def format_project_metadata(project: dict, user_id: str = None) -> dict:
        """Add formatted metadata to project record - PRESERVES ALL FIELDS"""
        
        if not project or not isinstance(project, dict):
            logger.warning(f"⚠️ Invalid project data passed to formatter: {type(project)} - {project}")
            return None
        
        logger.debug(f"🔧 Formatting project: {project.get('projectID', 'NO_ID')} with keys: {list(project.keys())}")
        
        # Start with ALL original project data
        formatted_project = project.copy()
        
        # Add/format specific fields without removing existing ones
        if "createdAt" in formatted_project:
            formatted_project["createdAt"] = format_date(project.get("createdAt", ""))
        if "updatedAt" in formatted_project:
            formatted_project["updatedAt"] = format_date(project.get("updatedAt", ""))
        
        # Add human-readable names without losing existing data
        created_by = project.get("createdBy")
        if created_by:
            try:
                formatted_project["createdByName"] = get_username(created_by)
            except Exception as e:
                logger.warning(f"Error getting creator name for {created_by}: {e}")
                formatted_project["createdByName"] = "Unknown"
        
        updated_by = project.get("updatedBy")
        if updated_by:
            try:
                formatted_project["updatedByName"] = get_username(updated_by)
            except Exception as e:
                logger.warning(f"Error getting updater name for {updated_by}: {e}")
                formatted_project["updatedByName"] = "Unknown"
        
        # Add client name if clientID exists
        client_id = project.get("clientID")
        if client_id:
            try:
                formatted_project["clientName"] = get_client_name(client_id)
            except Exception as e:
                logger.warning(f"Error getting client name for {client_id}: {e}")
                formatted_project["clientName"] = "Unknown Client"
        
        # Add contact name if contactID exists
        contact_id = project.get("contactID")
        if contact_id:
            try:
                formatted_project["contactName"] = get_contact_name(contact_id)
            except Exception as e:
                logger.warning(f"Error getting contact name for {contact_id}: {e}")
                formatted_project["contactName"] = "Unknown Contact"
        
        logger.debug(f"✅ Formatted project {project.get('projectID', 'NO_ID')} successfully")
        return formatted_project

    @staticmethod
    def batch_get_projects_by_ids(ids: List[str]) -> List[Dict[str, Any]]:
        """Enhanced batch get with detailed debugging"""
        if not ids:
            logger.warning("No IDs provided to batch_get_projects_by_ids")
            return []
        
        logger.info(f"🔍 Attempting to fetch {len(ids)} projects by IDs: {list(ids)[:3]}..." + (" (truncated)" if len(ids) > 3 else ""))
        
        all_items = []
        
        for i in range(0, len(ids), BATCH_SIZE):
            chunk_ids = ids[i:i+BATCH_SIZE]
            logger.debug(f"Processing chunk {i//BATCH_SIZE + 1}: {len(chunk_ids)} projects")
            
            try:
                for project_id in chunk_ids:
                    resp = PROJECTS_TABLE.get_item(Key={"projectID": project_id})
                    item = resp.get("Item")
                    if item:
                        all_items.append(item)
                    else:
                        logger.warning(f"Project {project_id} not found")
            except Exception as e:
                logger.error(f"❌ Error fetching projects in chunk {i//BATCH_SIZE + 1}: {e}")
        
        logger.info(f"🎯 Final batch get result: {len(all_items)} items retrieved from {len(ids)} requested")
        return all_items

    @staticmethod
    def scan_all_projects() -> List[Dict[str, Any]]:
        """Scan all projects from the table"""
        try:
            all_items = []
            
            logger.info("🔍 Starting scan of all projects...")
            response = PROJECTS_TABLE.scan()
            initial_items = response.get("Items", [])
            all_items.extend(initial_items)
            
            logger.info(f"📋 First scan page: {len(initial_items)} projects")
            
            # Handle pagination
            while "LastEvaluatedKey" in response:
                logger.debug("🔄 Scanning next page...")
                response = PROJECTS_TABLE.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                page_items = response.get("Items", [])
                all_items.extend(page_items)
                logger.debug(f"📋 Additional page: {len(page_items)} projects")
            
            logger.info(f"✅ Total projects scanned: {len(all_items)}")
            
            if all_items:
                sample_project = all_items[0]
                logger.info(f"📊 Sample project keys: {list(sample_project.keys())}")
                logger.info(f"📊 Sample project ID: {sample_project.get('projectID', 'MISSING')}")
            else:
                logger.warning("❌ No projects found in scan!")
            
            return all_items
            
        except Exception as e:
            logger.error(f"❌ Error scanning projects: {e}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            return []

    @staticmethod
    def get_projects_by_creators(creator_user_ids: List[str]) -> List[Dict[str, Any]]:
        """Get all projects created by specific users using GSI for optimal performance"""
        if not creator_user_ids:
            logger.warning("No creator user IDs provided")
            return []
        
        logger.info(f"🔍 Fetching projects created by {len(creator_user_ids)} creators: {creator_user_ids}")
        
        all_projects = []
        
        for creator_id in creator_user_ids:
            try:
                # Try GSI if available (RECOMMENDED)
                try:
                    logger.debug(f"Querying projects created by {creator_id} using createdBy-index GSI")
                    
                    response = PROJECTS_TABLE.query(
                        IndexName='createdBy-index',
                        KeyConditionExpression=Key('createdBy').eq(creator_id)
                    )
                    
                    creator_projects = response.get("Items", [])
                    all_projects.extend(creator_projects)
                    
                    logger.info(f"✅ GSI query for creator {creator_id}: found {len(creator_projects)} projects")
                    
                    # Handle pagination
                    while response.get("LastEvaluatedKey"):
                        logger.debug(f"Fetching additional projects for creator {creator_id} (pagination)")
                        response = PROJECTS_TABLE.query(
                            IndexName='createdBy-index',
                            KeyConditionExpression=Key('createdBy').eq(creator_id),
                            ExclusiveStartKey=response["LastEvaluatedKey"]
                        )
                        additional_projects = response.get("Items", [])
                        all_projects.extend(additional_projects)
                        logger.debug(f"✅ Pagination: got {len(additional_projects)} additional projects")
                    
                except Exception as gsi_error:
                    # Fallback to scan (less efficient but works)
                    logger.warning(f"GSI query failed for creator {creator_id}, falling back to scan: {gsi_error}")
                    
                    scan_response = PROJECTS_TABLE.scan(
                        FilterExpression=Attr('createdBy').eq(creator_id)
                    )
                    
                    creator_projects = scan_response.get("Items", [])
                    all_projects.extend(creator_projects)
                    
                    logger.info(f"✅ Scan fallback for creator {creator_id}: found {len(creator_projects)} projects")
                    
                    # Handle pagination for scan
                    while scan_response.get("LastEvaluatedKey"):
                        scan_response = PROJECTS_TABLE.scan(
                            FilterExpression=Attr('createdBy').eq(creator_id),
                            ExclusiveStartKey=scan_response["LastEvaluatedKey"]
                        )
                        additional_projects = scan_response.get("Items", [])
                        all_projects.extend(additional_projects)
                        logger.debug(f"✅ Scan pagination: got {len(additional_projects)} additional projects")
                    
            except Exception as e:
                logger.error(f"❌ Error fetching projects for creator {creator_id}: {e}")
        
        logger.info(f"✅ Total projects from {len(creator_user_ids)} creators: {len(all_projects)}")
        return all_projects

    @staticmethod
    def query_projects_by_client(client_id: str) -> List[Dict[str, Any]]:
        """Query projects by client ID using GSI"""
        try:
            all_items = []
            response = PROJECTS_TABLE.query(
                IndexName="clientID-index",
                KeyConditionExpression=Key("clientID").eq(client_id)
            )
            all_items.extend(response.get("Items", []))
            
            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = PROJECTS_TABLE.query(
                    IndexName="clientID-index",
                    KeyConditionExpression=Key("clientID").eq(client_id),
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                all_items.extend(response.get("Items", []))
            
            logger.debug(f"Queried {len(all_items)} projects for client {client_id}")
            return all_items
            
        except Exception as e:
            logger.error(f"Error querying projects by client {client_id}: {e}")
            return []

    @staticmethod
    def check_duplicate_project_name(project_name: str, client_id: str, exclude_project_id: str = None) -> bool:
        """Check if project name is already in use for a specific client"""
        try:
            query_result = PROJECTS_TABLE.query(
                IndexName="clientID-projectName-index",
                KeyConditionExpression=Key("clientID").eq(client_id) & Key("projectName").eq(project_name)
            )
            items = query_result.get("Items", [])
            
            if exclude_project_id:
                items = [item for item in items if item.get("projectID") != exclude_project_id]
            
            return len(items) > 0
        except Exception as e:
            logger.error(f"Error checking duplicate project name '{project_name}' for client {client_id}: {e}")
            return True

    @staticmethod
    def create_project(project_data: Dict[str, Any], requesting_user_id: str, sequences_table) -> Dict[str, Any]:
        """Create a new project with all validation"""
        username = get_username(requesting_user_id)
        
        # Generate unique IDs and timestamp
        current_time = datetime.utcnow().isoformat()
        project_identifier = str(uuid.uuid4())
        
        try:
            project_display_identifier = generate_unique_display_id("PRO", sequences_table)
        except Exception as e:
            logger.error(f"Display ID generation failed: {e}")
            raise Exception(f"ID generation failed: {str(e)}")

        # Build project record
        project_item = {
            "projectID": project_identifier,
            "displayID": project_display_identifier,
            "clientID": project_data["clientID"],
            "contactID": project_data.get("contactID"),
            "projectName": project_data["projectName"],
            "description": project_data.get("description", ""),
            "startDate": project_data.get("startDate"),
            "endDate": project_data.get("endDate"),
            "tasks": project_data.get("tasks", []),
            "status": project_data.get("status", "Active"),
            "createdByName": username,
            "updatedByName": username,
            "createdBy": requesting_user_id,
            "createdAt": current_time,
            "updatedAt": current_time,
            "updatedBy": requesting_user_id
        }

        # Handle privacy settings
        private_flag = project_data.get("private", False)
        allowed_users = project_data.get("allowedUsers")
        
        if private_flag:
            if not allowed_users or not isinstance(allowed_users, list):
                allowed_users = [requesting_user_id]
                logger.info(f"🔒 Setting default allowedUsers for private project: [{requesting_user_id}]")
            else:
                if not all(isinstance(user, str) and user.strip() for user in allowed_users):
                    raise ValueError("allowedUsers must contain valid user ID strings")
                if requesting_user_id not in allowed_users:
                    allowed_users.append(requesting_user_id)
                    logger.info(f"🔒 Added creator {requesting_user_id} to allowedUsers")
            
            project_item["private"] = True
            project_item["allowedUsers"] = allowed_users
            logger.info(f"🔒 Creating private project with {len(allowed_users)} allowed users")
            
        else:
            project_item["private"] = False
            logger.info("🔓 Creating public project (default behavior)")
            
            if allowed_users:
                logger.warning("⚠️ allowedUsers provided for public project - ignoring")

        # Save project to database
        PROJECTS_TABLE.put_item(Item=project_item)
        logger.info(f"✅ Created project {project_identifier} ({project_data['projectName']}) by user {requesting_user_id}")
        
        return project_item

    @staticmethod
    def auto_assign_creator(project_id: str, requesting_user_id: str, requesting_user_role: str, sequences_table):
        """Auto-assign creator to project"""
        try:
            assignment_identifier = str(uuid.uuid4())
            assignment_display_identifier = generate_unique_display_id("ASN", sequences_table)
            current_time = datetime.utcnow().isoformat()
            
            assignment_item = {
                "assignmentID": assignment_identifier,
                "displayID": assignment_display_identifier,
                "projectID": project_id,
                "userID": requesting_user_id,
                "role": requesting_user_role.lower() if requesting_user_role else "member",
                "assignedBy": requesting_user_id,
                "assignedAt": current_time,
                "status": "Active",
                "createdAt": current_time,
                "updatedAt": current_time,
            }
            
            ASSIGNMENTS_TABLE.put_item(Item=assignment_item)
            logger.info(f"✅ Auto-assigned creator {requesting_user_id} to project {project_id}")
        except Exception as assignment_error:
            logger.warning(f"Auto-assignment failed: {assignment_error}")

    @staticmethod
    def update_project(project_id: str, update_data: Dict[str, Any], requesting_user_id: str) -> Dict[str, Any]:
        """Update existing project with validation"""
        # Build update expression
        update_expressions = []
        expression_values = {}
        expression_names = {}
        
        # Handle privacy logic during update
        private_update = update_data.get("private")
        allowed_users_update = update_data.get("allowedUsers")
        
        if private_update is not None:
            logger.info(f"🔒 Updating project {project_id} private status to: {private_update}")
            
            # Handle reserved keyword for "private"
            expression_names["#private"] = "private"
            update_expressions.append("#private = :private")
            expression_values[":private"] = private_update
            
            if private_update:
                # Private project - handle allowed users
                if not allowed_users_update or not isinstance(allowed_users_update, list):
                    allowed_users_update = [requesting_user_id]
                    logger.debug(f"Auto-creating allowedUsers list with creator: {requesting_user_id}")
                elif requesting_user_id not in allowed_users_update:
                    allowed_users_update.append(requesting_user_id)
                    logger.debug(f"Adding creator to allowedUsers: {requesting_user_id}")
                
                update_expressions.append("allowedUsers = :allowedUsers")
                expression_values[":allowedUsers"] = allowed_users_update
            else:
                # Public project - remove allowed users
                update_expressions.append("REMOVE allowedUsers")
                
        elif allowed_users_update is not None:
            # Only updating allowed users for existing private project
            existing_project = PROJECTS_TABLE.get_item(Key={"projectID": project_id}).get("Item", {})
            current_private = existing_project.get("private", False)
            
            if current_private:
                logger.info(f"🔄 Updating allowedUsers for private project {project_id}")
                
                if not isinstance(allowed_users_update, list):
                    allowed_users_update = [requesting_user_id]
                elif requesting_user_id not in allowed_users_update:
                    allowed_users_update.append(requesting_user_id)
                
                update_expressions.append("allowedUsers = :allowedUsers")
                expression_values[":allowedUsers"] = allowed_users_update
        
        # Handle other updatable fields
        for input_field in UPDATABLE_FIELDS:
            if input_field in update_data and input_field not in ["private", "allowedUsers"]:
                if input_field == "status":  # Reserved word in DynamoDB
                    update_expressions.append("#status = :status")
                    expression_values[":status"] = update_data[input_field]
                    expression_names["#status"] = "status"
                else:
                    update_expressions.append(f"{input_field} = :{input_field}")
                    expression_values[f":{input_field}"] = update_data[input_field]
        
        # Add audit fields
        update_expressions.extend(["updatedAt = :updatedAt", "updatedBy = :updatedBy", "updatedByName = :updatedByName"])
        expression_values.update({
            ":updatedAt": datetime.utcnow().isoformat(),
            ":updatedBy": requesting_user_id,
            ":updatedByName": get_user_name(requesting_user_id)
        })
        
        if len(update_expressions) <= 3:  # Only audit fields
            raise ValueError("No fields to update")
        
        # Execute update
        update_request = {
            "Key": {"projectID": project_id},
            "UpdateExpression": "SET " + ", ".join([expr for expr in update_expressions if not expr.startswith("REMOVE")]),
            "ExpressionAttributeValues": expression_values,
            "ReturnValues": "ALL_NEW"
        }
        
        # Add REMOVE expression if needed
        remove_expressions = [expr.replace("REMOVE ", "") for expr in update_expressions if expr.startswith("REMOVE")]
        if remove_expressions:
            if "SET" in update_request["UpdateExpression"]:
                update_request["UpdateExpression"] += " REMOVE " + ", ".join(remove_expressions)
            else:
                update_request["UpdateExpression"] = "REMOVE " + ", ".join(remove_expressions)
        
        if expression_names:
            update_request["ExpressionAttributeNames"] = expression_names
        
        response = PROJECTS_TABLE.update_item(**update_request)
        updated_item = response.get("Attributes", {})
        
        logger.info(f"✅ Updated project {project_id} by user {requesting_user_id}")
        
        if private_update is not None:
            logger.info(f"🔒 Private status updated for project {project_id}: {private_update}")
            if private_update and allowed_users_update:
                logger.info(f"👥 Allowed users set: {allowed_users_update}")
        
        return updated_item

    @staticmethod
    def delete_project(project_id: str, requesting_user_id: str = None, force: bool = False):
        """Delete a project from the database with optional parameters for compatibility"""
        PROJECTS_TABLE.delete_item(Key={"projectID": project_id})
        logger.info(f"✅ Successfully deleted project {project_id}")
        
        # Return consistent format for compatibility
        return {
            "dependencies": {},
            "deletedBy": requesting_user_id,
            "deletedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod 
    def delete_project_assignments(project_id: str):
        """Delete all assignments for a project"""
        try:
            assignments_resp = ASSIGNMENTS_TABLE.query(
                IndexName="projectID-index",
                KeyConditionExpression=Key("projectID").eq(project_id)
            )
            for assignment in assignments_resp.get("Items", []):
                ASSIGNMENTS_TABLE.delete_item(Key={"assignmentID": assignment["assignmentID"]})
            logger.info(f"Deleted {len(assignments_resp.get('Items', []))} assignments for project {project_id}")
        except Exception as assignment_error:
            logger.warning(f"Error deleting assignments for project {project_id}: {assignment_error}")

    @staticmethod
    def apply_privacy_filter(projects: List[Dict[str, Any]], user_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Apply privacy filtering to a list of projects"""
        filtered_items = []
        privacy_stats = {"public": 0, "private_allowed": 0, "private_denied": 0}
        
        for project in projects:
            project_id = project.get("projectID", "unknown")
            
            # Only check the private field
            is_private = project.get("private", False)
            allowed_users = project.get("allowedUsers", [])
            
            if not is_private:
                filtered_items.append(project)
                privacy_stats["public"] += 1
                logger.debug(f"✅ Including public project {project_id}")
            else:
                if user_id in allowed_users:
                    filtered_items.append(project)
                    privacy_stats["private_allowed"] += 1
                    logger.debug(f"✅ Including private project {project_id} - user in allowedUsers")
                else:
                    privacy_stats["private_denied"] += 1
                    logger.debug(f"❌ Excluding private project {project_id} - user not in allowedUsers")
        
        logger.info(f"🔒 Privacy filtering: {privacy_stats['public']} public, {privacy_stats['private_allowed']} private allowed, {privacy_stats['private_denied']} private denied")
        
        return filtered_items, privacy_stats

    @staticmethod
    def handle_create_project_request(request_body, requesting_user_id, requesting_user_role, requesting_user_privileges):
        """Handle complete project creation request - moved from handler"""
        # Enhanced authorization check using policy engine
        if not policy_service.can_do(requesting_user_id, "Projects", "create"):
            logger.warning(f"Create denied for user {requesting_user_id}: insufficient permissions")
            
            if policy_service.policy_engine_available:
                scope_result = policy_service.get_allowed_record_ids(requesting_user_id, "Projects", "create")
                raise PermissionError(f"Not authorized to create projects. Pattern: {scope_result.get('pattern', 'unknown')}")
            else:
                raise PermissionError("Not authorized to create projects")

        # Validate required fields
        project_name = (request_body.get("projectName") or "").strip()
        client_identifier = request_body.get("clientID")
        
        missing_fields = []
        if not project_name:
            missing_fields.append("projectName")
        if not client_identifier:
            missing_fields.append("clientID")
        
        if missing_fields:
            raise ValueError(f"Required fields missing: {', '.join(missing_fields)}")

        # Check if client exists and user has access
        client_resp = CLIENTS_TABLE.get_item(Key={"clientID": client_identifier})
        if not client_resp.get("Item"):
            raise ValueError("Client not found")
        
        # Check if user can view the client
        if policy_service.policy_engine_available and not policy_service.can_access_record(requesting_user_id, "Clients", "view", client_identifier):
            raise PermissionError("Not authorized to create projects for this client")

        # Check for duplicate project name per client
        if ProjectService.check_duplicate_project_name(project_name, client_identifier):
            raise ValueError("Project name already exists for this client")

        # Validate contact if provided
        contact_identifier = request_body.get("contactID")
        if contact_identifier:
            contact_resp = CONTACTS_TABLE.get_item(Key={"contactID": contact_identifier})
            if not contact_resp.get("Item"):
                raise ValueError("Contact not found")
            
            contact_item = contact_resp["Item"]
            if contact_item.get("clientID") != client_identifier:
                raise ValueError("Contact does not belong to the specified client")

        # Create project using service
        project_item = ProjectService.create_project(request_body, requesting_user_id, SEQUENCES_TABLE)
        
        # Auto-assign creator to project if enabled
        if request_body.get("autoAssign", True):
            ProjectService.auto_assign_creator(
                project_item["projectID"], 
                requesting_user_id, 
                requesting_user_role, 
                SEQUENCES_TABLE
            )
        
        return {
            "status": 201,
            "data": {
                "message": "Project created successfully",
                "project": {
                    "projectID": project_item["projectID"],
                    "displayID": project_item["displayID"],
                    "projectName": project_item["projectName"],
                    "clientID": project_item["clientID"],
                    "contactID": project_item.get("contactID"),
                    "status": project_item["status"],
                    "privacy": project_item.get("privacy", "public"),
                    "createdAt": project_item["createdAt"],
                    "createdBy": project_item["createdBy"],
                    "createdByName": project_item["createdByName"],
                    "updatedByName": project_item["updatedByName"]
                }
            }
        }

    @staticmethod
    def handle_get_projects_request(query_params, requesting_user_id, requesting_user_role, requesting_user_privileges):
        """Handle complete get projects request - moved from handler"""
        project_id = query_params.get("projectID")
        client_id_filter = query_params.get("clientID")
        view_type = query_params.get("view", "full")
        include_permissions = query_params.get("includePermissions", "").lower() == "true"
        debug_mode = query_params.get("debug", "").lower() == "true"
        
        logger.info(f"Project GET request: user={requesting_user_id}, view={view_type}, projectID={project_id}, clientFilter={client_id_filter}, debug={debug_mode}")
        
        # Enhanced debug endpoint
        if debug_mode and policy_service.policy_engine_available:
            debug_info = policy_service.get_user_permissions_debug(requesting_user_id, "Projects")
            
            # Add creator-based access info
            access_filter = policy_service.get_accessible_records_filter(requesting_user_id, "Projects", "view")
            debug_info["creatorBasedAccess"] = {
                "hasCreatorAccess": "selected_by_creator" in access_filter.get("scopes", []),
                "filterType": access_filter.get("type", "none"),
                "creatorIds": access_filter.get("creator_ids", [])[:5],
                "creatorCount": len(access_filter.get("creator_ids", [])),
                "supportsCreatorBased": True
            }
            
            return {
                "status": 200,
                "data": {"debugInfo": debug_info}
            }
        
        if project_id:
            return ProjectService._handle_specific_project_view(requesting_user_id, project_id, include_permissions)
        else:
            return ProjectService._handle_projects_list_view(requesting_user_id, view_type, include_permissions, client_id_filter)

    @staticmethod
    def handle_permissions_test_request(query_params, user_id):
        """Handle permissions test request - moved from handler"""
        test_user_id = query_params.get("testUserId", user_id)
        project_id = query_params.get("projectID")
        
        if not policy_service.policy_engine_available:
            raise Exception("Policy engine not available")
        
        if project_id:
            # Test specific project permissions
            test_results = ProjectService._test_project_permissions(test_user_id, project_id)
        else:
            # Get general permissions summary
            test_results = ProjectService._get_project_permissions_summary(test_user_id)
        
        return {
            "status": 200,
            "data": {
                "testResults": test_results,
                "currentUser": user_id,
                "testUser": test_user_id
            }
        }

    @staticmethod
    def _handle_specific_project_view(user_id: str, project_id: str, include_permissions: bool = False) -> dict:
        """Handle single project retrieval with authorization and privacy"""
        
        # Direct policy engine authorization check
        if not policy_service.can_access_record(user_id, "Projects", "view", project_id):
            logger.warning(f"Project view denied for user {user_id}, project {project_id}")
            
            if policy_service.policy_engine_available:
                scope_result = policy_service.get_allowed_record_ids(user_id, "Projects", "view")
                access_filter = policy_service.get_accessible_records_filter(user_id, "Projects", "view")
                
                error_msg = f"Not authorized to view this project. Pattern: {access_filter.get('pattern', 'unknown')}"
                if "selected_by_creator" in scope_result.get("scopes", []):
                    error_msg += " (You have creator-based access - check if you can view projects created by specific users)"
                
                raise PermissionError(error_msg)
            else:
                raise PermissionError("Not authorized to view this project")
        
        # Fetch the project
        resp = PROJECTS_TABLE.get_item(Key={"projectID": project_id})
        project = resp.get("Item")
        if not project:
            raise ValueError("Project not found")
        
        # Privacy check with dual field support and detailed logging
        private_flag = project.get("private", False)
        allowed_users = project.get("allowedUsers", [])
        
        if private_flag and user_id not in allowed_users:
            logger.warning(f"🔒 Private project access denied: user {user_id} not in allowedUsers for project {project_id}")
            raise PermissionError("Not authorized to view this private project")
        
        # Format with metadata
        formatted_project = ProjectService.format_project_metadata(project, user_id if include_permissions else None)
        
        # Add access method info for debugging
        if policy_service.policy_engine_available:
            access_filter = policy_service.get_accessible_records_filter(user_id, "Projects", "view")
            formatted_project["_accessInfo"] = {
                "accessMethod": access_filter.get("pattern", "unknown"),
                "hasCreatorAccess": "selected_by_creator" in access_filter.get("scopes", []),
                "createdBy": project.get("createdBy"),
                "isOwnProject": project.get("createdBy") == user_id,
                "private": project.get("private", False)
            }
        
        logger.info(f"✅ Successfully retrieved project {project_id} for user {user_id}")
        
        return {
            "status": 200,
            "data": {
                "project": formatted_project,
                "accessGranted": True,
                "retrievedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
        }

    @staticmethod
    def _handle_projects_list_view(user_id: str, view_type: str, include_permissions: bool = False, 
                                  client_id_filter: str = None) -> dict:
        """Project list view with creator-based selection support and privacy filtering"""
        # Get access filter from policy engine
        access_filter = policy_service.get_accessible_records_filter(user_id, "Projects", "view")
        filter_type = access_filter.get("type", "none")
        active_scopes = access_filter.get("scopes", [])
        pattern = access_filter.get("pattern", "unknown")
        
        logger.info(f"Project list view for user {user_id}: filter_type={filter_type}, pattern={pattern}, scopes={active_scopes}")
        
        # Apply client filter if provided
        if client_id_filter:
            logger.info(f"Applying client filter: {client_id_filter}")
        
        if filter_type == "all":
            # User has access to all projects
            if client_id_filter:
                items = ProjectService.query_projects_by_client(client_id_filter)
            else:
                items = ProjectService.scan_all_projects()
            logger.info(f"📋 All access: {len(items)} total projects")
            
        elif filter_type == "all_except_denied":
            # All projects except explicitly denied ones
            denied_ids = access_filter.get("denied_ids", [])
            
            logger.info(f"📋 All access with {len(denied_ids)} denied projects")
            
            if client_id_filter:
                all_items = ProjectService.query_projects_by_client(client_id_filter)
            else:
                all_items = ProjectService.scan_all_projects()
            
            items = [item for item in all_items if item.get("projectID") not in denied_ids]
            
        elif filter_type == "specific":
            # User has access to specific projects (individual IDs + creator-based)
            allowed_ids = access_filter.get("allowed_ids", [])
            
            logger.info(f"📋 Specific access: {len(allowed_ids)} allowed project IDs")
            
            if not allowed_ids:
                items = []
            else:
                items = ProjectService.batch_get_projects_by_ids(allowed_ids)
                
                # Apply client filter if provided (post-fetch filtering)
                if client_id_filter:
                    items = [item for item in items if item.get("clientID") == client_id_filter]

        elif filter_type == "creator_based":
            # User has access based on creators they can see
            creator_ids = access_filter.get("creator_ids", [])
            denied_ids = access_filter.get("denied_ids", [])
            
            logger.info(f"📋 Creator-based access: {len(creator_ids)} allowed creators")
            
            if not creator_ids:
                items = []
            else:
                # Get all projects created by these users
                items = ProjectService.get_projects_by_creators(creator_ids)
                
                # Apply client filter if provided
                if client_id_filter:
                    items = [item for item in items if item.get("clientID") == client_id_filter]
                
                # Remove any explicitly denied projects
                if denied_ids:
                    items = [item for item in items if item.get("projectID") not in denied_ids]

        elif filter_type == "mixed":
            # Combination of specific IDs and creator-based access
            allowed_ids = access_filter.get("allowed_ids", [])
            creator_ids = access_filter.get("creator_ids", [])
            denied_ids = access_filter.get("denied_ids", [])
            
            items = []
            
            # Get specific projects by ID
            if allowed_ids:
                specific_items = ProjectService.batch_get_projects_by_ids(allowed_ids)
                items.extend(specific_items)
            
            # Get projects by creators
            if creator_ids:
                creator_items = ProjectService.get_projects_by_creators(creator_ids)
                items.extend(creator_items)
            
            # Remove duplicates (by projectID)
            seen_ids = set()
            unique_items = []
            for item in items:
                project_id = item.get("projectID")
                if project_id and project_id not in seen_ids:
                    seen_ids.add(project_id)
                    unique_items.append(item)
            
            items = unique_items
            
            # Apply client filter if provided
            if client_id_filter:
                items = [item for item in items if item.get("clientID") == client_id_filter]
            
            # Remove explicitly denied projects
            if denied_ids:
                items = [item for item in items if item.get("projectID") not in denied_ids]
                
        else:
            # No access
            items = []
        
        # Privacy filtering for projects
        filtered_items, privacy_stats = ProjectService.apply_privacy_filter(items, user_id)
        
        # Use filtered_items for further processing
        valid_items = [item for item in filtered_items if item is not None and isinstance(item, dict)]
        
        # Format items based on view type
        formatted_items = []
        for i, project in enumerate(valid_items):
            try:
                formatted = ProjectService.format_project_metadata(project, user_id if include_permissions else None)
                if formatted is not None:
                    formatted_items.append(formatted)
            except Exception as e:
                logger.error(f"❌ Error formatting project {i}: {e}")
        
        logger.info(f"✅ Successfully formatted {len(formatted_items)} projects")
        
        # Enhanced response with creator-based pattern info
        response_data = {
            "projects": formatted_items,
            "totalCount": len(formatted_items),
            "scope": "+".join(active_scopes) if active_scopes else filter_type,
            "activeScopes": active_scopes,
            "policyEngineAvailable": policy_service.policy_engine_available,
            "filterType": filter_type,
            "pattern": pattern,
            "clientFilter": client_id_filter
        }
        
        # Add statistics for debugging
        if "stats" in access_filter:
            response_data["policyStats"] = access_filter["stats"]
        
        return {
            "status": 200,
            "data": response_data
        }

    @staticmethod
    def _get_project_permissions_summary(user_id: str, project_id: str = None):
        """Get a comprehensive summary of project permissions for debugging"""
        if not policy_service.policy_engine_available:
            return {"error": "Policy engine not available"}
        
        summary = policy_service.get_user_scopes_summary(user_id, "Projects")
        
        # Add pattern and statistics information
        for action in ["view", "create", "modify", "delete"]:
            scope_result = policy_service.get_allowed_record_ids(user_id, "Projects", action)
            access_filter = policy_service.get_accessible_records_filter(user_id, "Projects", action)
            
            if action in summary.get("actions", {}):
                summary["actions"][action].update({
                    "pattern": access_filter.get("pattern", "unknown"),
                    "filterType": access_filter.get("type", "none"),
                    "stats": scope_result.get("stats", {}),
                    "hasAllAccess": scope_result.get("all", False),
                    "deniedCount": len(scope_result.get("denied_ids", []))
                })
        
        if project_id:
            # Add specific project permissions
            summary["specificProject"] = {
                "projectID": project_id,
                "canView": policy_service.can_access_record(user_id, "Projects", "view", project_id),
                "canModify": policy_service.can_access_record(user_id, "Projects", "modify", project_id),
                "canDelete": policy_service.can_access_record(user_id, "Projects", "delete", project_id),
                "canChangeClient": policy_service.can_access_record(user_id, "Projects", "client_change", project_id)
            }
        
        return summary

    @staticmethod
    def _test_project_permissions(user_id: str, project_id: str):
        """Test all permission patterns for a specific project"""
        if not policy_service.policy_engine_available:
            return {"error": "Policy engine not available"}
        
        test_results = {
            "user_id": user_id,
            "project_id": project_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "permissions": {},
            "scopes": {}
        }
        
        # Test each action
        for action in ["view", "create", "modify", "delete", "client_change"]:
            # Individual record access
            can_access = policy_service.can_access_record(user_id, "Projects", action, project_id)
            
            # Scope information
            scope_result = policy_service.get_allowed_record_ids(user_id, "Projects", action)
            access_filter = policy_service.get_accessible_records_filter(user_id, "Projects", action)
            
            test_results["permissions"][action] = {
                "canAccess": can_access,
                "pattern": access_filter.get("pattern", "unknown"),
                "hasAllAccess": scope_result.get("all", False),
                "inAllowedIds": project_id in scope_result.get("ids", set()),
                "inDeniedIds": project_id in scope_result.get("denied_ids", set())
            }
            
            test_results["scopes"][action] = {
                "scopes": scope_result.get("scopes", []),
                "allowedCount": len(scope_result.get("ids", set())) if not scope_result.get("all", False) else "unlimited",
                "deniedCount": len(scope_result.get("denied_ids", set())),
                "stats": scope_result.get("stats", {})
            }
        
        return test_results

    @staticmethod
    def handle_update_project_request(request_body, requesting_user_id, requesting_user_role):
        """Handle complete project update request - moved from handler"""
        project_identifier = request_body.get("projectID")
        if not project_identifier:
            raise ValueError("projectID is required")
        
        # Fetch existing project first
        existing_project = PROJECTS_TABLE.get_item(Key={"projectID": project_identifier}).get("Item")
        if not existing_project:
            raise ValueError("Project not found")
        
        # Privacy check with dual field support
        private_flag = existing_project.get("private", False)
        allowed_users = existing_project.get("allowedUsers", [])
        
        if private_flag and requesting_user_id not in allowed_users:
            raise PermissionError("Not authorized to update this private project")
        
        # Policy check
        if not policy_service.can_access_record(requesting_user_id, "Projects", "modify", project_identifier):
            raise PermissionError("Not authorized to modify this project")
        
        # Client change validation
        new_client_identifier = request_body.get("clientID")
        current_client_identifier = existing_project.get("clientID")
        
        if new_client_identifier and new_client_identifier != current_client_identifier:
            # Check client change permission
            if not policy_service.can_access_record(requesting_user_id, "Projects", "client_change", project_identifier):
                raise PermissionError("Not authorized to change client for this project")
            
            # Validate new client exists
            new_client_lookup = CLIENTS_TABLE.get_item(Key={"clientID": new_client_identifier}).get("Item")
            if not new_client_lookup:
                raise ValueError("New client not found")
            
            # Check if user can view the new client
            if not policy_service.can_access_record(requesting_user_id, "Clients", "view", new_client_identifier):
                raise PermissionError("Not authorized to assign project to this client")

        effective_client_identifier = new_client_identifier or current_client_identifier

        # Check for duplicate project name if being changed
        new_project_name = request_body.get("projectName")
        if new_project_name and new_project_name != existing_project.get("projectName"):
            if ProjectService.check_duplicate_project_name(new_project_name, effective_client_identifier, project_identifier):
                raise ValueError("Project name already exists for this client")

        # Validate contact if being changed
        new_contact_id = request_body.get("contactID")
        if new_contact_id and new_contact_id != existing_project.get("contactID"):
            contact_resp = CONTACTS_TABLE.get_item(Key={"contactID": new_contact_id})
            if not contact_resp.get("Item"):
                raise ValueError("Contact not found")
            
            contact_item = contact_resp["Item"]
            if contact_item.get("clientID") != effective_client_identifier:
                raise ValueError("Contact does not belong to the client")

        # Update project using service
        updated_item = ProjectService.update_project(project_identifier, request_body, requesting_user_id)
        
        # Format the updated project for response
        formatted_project = ProjectService.format_project_metadata(updated_item, requesting_user_id)
        
        return {
            "status": 200,
            "data": {
                "message": "Project updated successfully",
                "project": formatted_project,
                "updatedFields": [field for field in request_body.keys() if field != "projectID"],
                "private": updated_item.get("private", False)
            }
        }

    @staticmethod
    def handle_delete_project_request(request_body, requesting_user_id):
        """Handle complete project delete request - moved from handler"""

        # Accept single ID or list
        project_ids = []
        if "projectID" in request_body:
            project_ids = [request_body["projectID"]]
        elif "projectIDs" in request_body:
            project_ids = request_body["projectIDs"]
        else:
            raise ValueError("projectID or projectIDs is required")

        results = []
        for project_identifier in project_ids:
            # Fetch existing project
            existing_project = PROJECTS_TABLE.get_item(Key={"projectID": project_identifier}).get("Item")
            if not existing_project:
                raise ValueError(f"Project not found: {project_identifier}")

            # Privacy check
            private_flag = existing_project.get("private", False)
            allowed_users = existing_project.get("allowedUsers", [])
            if private_flag and requesting_user_id not in allowed_users:
                raise PermissionError(f"Not authorized to delete private project {project_identifier}")

            # Policy check
            if not policy_service.can_access_record(requesting_user_id, "Projects", "delete", project_identifier):
                raise PermissionError(f"Not authorized to delete project {project_identifier}")

            # Check for dependencies and confirm deletion
            force_delete = request_body.get("force", False)

            # Perform the deletion
            deletion_result = ProjectService.delete_project(
                project_identifier, 
                requesting_user_id,
                force_delete
            )

            results.append({
                "projectID": project_identifier,
                "deletedAt": deletion_result.get("deletedAt"),
                "deletedBy": requesting_user_id,
                "dependencies": deletion_result.get("dependencies", {}),
                "forceDelete": force_delete,
                "message": "Project deleted successfully"
            })

        return {
            "status": 200,
            "data": results if len(results) > 1 else results[0]
        }
