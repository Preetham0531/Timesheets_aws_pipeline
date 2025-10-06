import logging
from typing import Dict, Any, List
from boto3.dynamodb.conditions import Attr

from utils import PROJECTS_TABLE

# ========= LOGGING =========
logger = logging.getLogger("project_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class ProjectModel:
    """
    Data access layer for project operations.
    Handles database interactions for projects.
    """
    
    def __init__(self):
        self.projects_table = PROJECTS_TABLE

    def get_projects_by_contact_id(self, contact_id: str) -> List[Dict[str, Any]]:
        """
        Get all projects linked to a contactID
        """
        if not contact_id:
            logger.warning("No contact_id provided to get_projects_by_contact_id")
            return []
        
        logger.info(f"Searching for projects with contactID: {contact_id}")
        
        try:
            all_projects = []
            
            # Use scan to find projects with matching contactID
            logger.info("Using SCAN method to find projects...")
            
            response = self.projects_table.scan(
                FilterExpression=Attr("contactID").eq(contact_id)
            )
            projects = response.get("Items", [])
            all_projects.extend(projects)
            
            logger.info(f"First scan page: found {len(projects)} projects")
            
            # Handle pagination for scan
            page_count = 1
            while response.get("LastEvaluatedKey"):
                page_count += 1
                logger.debug(f"Scanning page {page_count}...")
                
                response = self.projects_table.scan(
                    FilterExpression=Attr("contactID").eq(contact_id),
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                additional_projects = response.get("Items", [])
                all_projects.extend(additional_projects)
                
                logger.debug(f"Page {page_count}: found {len(additional_projects)} additional projects")
            
            logger.info(f"✅ Scan complete: found {len(all_projects)} total projects across {page_count} pages")
            
            # Log what we found for debugging
            if all_projects:
                logger.info(f"Projects found for contact {contact_id}:")
                for i, project in enumerate(all_projects):
                    project_id = project.get("projectID", "NO_ID")
                    project_name = project.get("projectName", "NO_NAME")
                    project_contact_id = project.get("contactID", "NO_CONTACT_ID")
                    logger.info(f"   {i+1}. Project: {project_id}")
                    logger.info(f"      Name: {project_name}")
                    logger.info(f"      ContactID: {project_contact_id}")
                    logger.info(f"      Match: {'✅' if project_contact_id == contact_id else '❌'}")
            else:
                logger.warning(f"No projects found for contact {contact_id}")
                
                # Debug: Check if there are any projects in the table
                logger.info("Checking if projects table has any data...")
                try:
                    sample_response = self.projects_table.scan(Limit=5)
                    sample_projects = sample_response.get("Items", [])
                    logger.info(f"Sample projects in table: {len(sample_projects)}")
                    
                    if sample_projects:
                        logger.info("Sample project structure:")
                        sample = sample_projects[0]
                        logger.info(f"   Keys: {list(sample.keys())}")
                        logger.info(f"   ProjectID: {sample.get('projectID', 'MISSING')}")
                        logger.info(f"   ContactID: {sample.get('contactID', 'MISSING')}")
                        logger.info(f"   ProjectName: {sample.get('projectName', 'MISSING')}")
                    else:
                        logger.warning("Projects table appears to be empty!")
                        
                except Exception as debug_error:
                    logger.error(f"Error during debug scan: {debug_error}")
            
            return all_projects
            
        except Exception as e:
            logger.error(f"Error fetching projects for contactID {contact_id}: {e}")
            return []

logger.info("✅ ProjectModel initialized")