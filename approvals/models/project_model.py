# Data access layer for project records
import boto3
import os
import logging
from typing import Optional
from utils import PROJECTS_TABLE

logger = logging.getLogger("project_model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class ProjectModel:
    """Data access layer for project records"""
    
    def __init__(self):
        self.table = PROJECTS_TABLE

    def get_creator_id(self, project_id: str) -> Optional[str]:
        """Get project creator ID with robust schema support"""
        try:
            # Try different possible schema keys
            keys_to_try = ("createdBy", "CreatedBy", "ownerID", "OwnerID")
            response = self.table.get_item(
                Key={"projectID": project_id},
                ProjectionExpression=", ".join(keys_to_try)
            )
            item = response.get("Item") or {}
            for key in keys_to_try:
                value = item.get(key)
                if value:
                    return value
            return None
        except Exception as e:
            logger.debug(f"Could not resolve project creator for {project_id}: {e}")
            return None

logger.info("✅ Project model initialized")