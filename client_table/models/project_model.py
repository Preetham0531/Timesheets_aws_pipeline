"""
Project Data Model
Handles all database operations for project records.
"""

import logging
from typing import Any, Dict, List
from boto3.dynamodb.conditions import Key, Attr
from utils import PROJECTS_TABLE

logger = logging.getLogger("project_model")

class ProjectModel:
    """Data access layer for project operations"""
    
    def __init__(self):
        self.table = PROJECTS_TABLE

    def get_client_projects_with_policy(self, user_id: str, client_id: str) -> List[Dict[str, Any]]:
        """Get projects for a specific client with policy engine filtering"""
        try:
            # Import policy service here to avoid circular imports
            from services.policy_service import PolicyService
            policy_service = PolicyService()
            
            if not policy_service.policy_available:
                logger.warning("Policy engine not available, returning empty projects list")
                return []
            
            projects_access = policy_service.get_accessible_records_filter(user_id, "view")
            access_pattern = projects_access.get("pattern", "none")
            
            logger.info(f"Projects access pattern for user {user_id}: {access_pattern}")
            
            if access_pattern == "none":
                logger.info(f"User {user_id} has no projects access")
                return []
            
            try:
                logger.info(f"Querying projects for client {client_id} using clientID-index GSI")
                
                response = self.table.query(
                    IndexName='clientID-index',
                    KeyConditionExpression=Key('clientID').eq(client_id)
                )
                
                all_projects = response.get("Items", [])
                logger.info(f"Query successful: {len(all_projects)} projects found for client {client_id}")
                
                # Handle pagination
                while response.get("LastEvaluatedKey"):
                    logger.info(f"Fetching additional projects (pagination)...")
                    response = self.table.query(
                        IndexName='clientID-index',
                        KeyConditionExpression=Key('clientID').eq(client_id),
                        ExclusiveStartKey=response["LastEvaluatedKey"]
                    )
                    additional_projects = response.get("Items", [])
                    all_projects.extend(additional_projects)
                    logger.info(f"Fetched {len(additional_projects)} additional projects")
                
                # Apply policy filtering
                filtered_projects = self._apply_projects_policy_filter(user_id, all_projects, projects_access, access_pattern)
                
                logger.info(f"After policy filtering: {len(filtered_projects)} projects accessible for user {user_id}")
                
                return filtered_projects
                
            except Exception as e:
                logger.error(f"Error querying projects: {e}")
                return []
            
        except Exception as e:
            logger.error(f"Error getting client projects: {e}")
            return []

    def _apply_projects_policy_filter(self, user_id: str, all_projects: List[Dict[str, Any]], 
                                    projects_access: Dict[str, Any], access_pattern: str) -> List[Dict[str, Any]]:
        """Apply policy engine filtering to projects list"""
        try:
            if access_pattern == "all":
                logger.info(f"User {user_id} has 'all' access to projects")
                return all_projects
                
            elif access_pattern == "all_except_denied":
                denied_ids = set(projects_access.get("denied_ids", []))
                logger.info(f"User {user_id} has 'all_except_denied' access, {len(denied_ids)} denied projects")
                
                filtered_projects = []
                for project in all_projects:
                    project_id = self._get_project_id(project)
                    if project_id and project_id not in denied_ids:
                        filtered_projects.append(project)
                    elif project_id in denied_ids:
                        logger.debug(f"Project {project_id} denied for user {user_id}")
                
                return filtered_projects
                
            elif access_pattern in ["specific", "specific_with_precedence"]:
                allowed_ids = set(projects_access.get("allowed_ids", []))
                denied_ids = set(projects_access.get("denied_ids", []))
                
                logger.info(f"User {user_id} has '{access_pattern}' access: {len(allowed_ids)} allowed, {len(denied_ids)} denied")
                
                filtered_projects = []
                for project in all_projects:
                    project_id = self._get_project_id(project)
                    if project_id:
                        if project_id in allowed_ids and project_id not in denied_ids:
                            filtered_projects.append(project)
                        elif project_id in denied_ids:
                            logger.debug(f"Project {project_id} explicitly denied for user {user_id}")
                        elif project_id not in allowed_ids:
                            logger.debug(f"Project {project_id} not in allowed list for user {user_id}")
                
                return filtered_projects
            
            else:
                logger.warning(f"Unknown access pattern '{access_pattern}' for user {user_id}, denying access")
                return []
                
        except Exception as e:
            logger.error(f"Error applying policy filter: {e}")
            return []

    def _get_project_id(self, project: Dict[str, Any]) -> str:
        """Extract project ID from project record"""
        project_id = project.get("projectID")
        
        if project_id:
            return str(project_id)
        
        # Fallback to other possible field names
        for field in ["ProjectID", "project_id", "id", "ID"]:
            if field in project:
                logger.warning(f"Using fallback field '{field}' for project ID")
                return str(project[field])
        
        logger.warning(f"No project ID found in project record with keys: {list(project.keys())}")
        return ""