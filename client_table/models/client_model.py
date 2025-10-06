"""
Client Data Model
Handles all database operations for client records.
"""

import logging
from typing import Any, Dict, List, Optional, Set
from boto3.dynamodb.conditions import Attr, Key
from utils import CLIENTS_TABLE

logger = logging.getLogger("client_model")

class ClientModel:
    """Data access layer for client operations"""
    
    def __init__(self):
        self.table = CLIENTS_TABLE

    def create_client(self, client_record: Dict[str, Any]) -> None:
        """Create a new client record"""
        try:
            self.table.put_item(Item=client_record)
            logger.debug(f"Created client {client_record.get('clientID')}")
        except Exception as e:
            logger.error(f"Error creating client: {e}")
            raise

    def get_client_by_id(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get a client by ID"""
        try:
            response = self.table.get_item(Key={"clientID": client_id})
            return response.get("Item")
        except Exception as e:
            logger.error(f"Error getting client {client_id}: {e}")
            raise

    def update_client(self, client_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a client record"""
        try:
            update_request = {
                "Key": {"clientID": client_id},
                "UpdateExpression": "SET " + ", ".join(update_data["expressions"]),
                "ExpressionAttributeValues": update_data["values"],
                "ReturnValues": "ALL_NEW"
            }
            
            if update_data["names"]:
                update_request["ExpressionAttributeNames"] = update_data["names"]
            
            response = self.table.update_item(**update_request)
            return response.get("Attributes", {})
        except Exception as e:
            logger.error(f"Error updating client {client_id}: {e}")
            raise

    def delete_client(self, client_id: str) -> None:
        """Delete a client record"""
        try:
            self.table.delete_item(Key={"clientID": client_id})
            logger.debug(f"Deleted client {client_id}")
        except Exception as e:
            logger.error(f"Error deleting client {client_id}: {e}")
            raise

    def check_duplicate_company_name(self, company_name: str, exclude_client_id: str = None) -> bool:
        """Check if company name is already in use"""
        try:
            scan_result = self.table.scan(FilterExpression=Attr("companyName").eq(company_name))
            items = scan_result.get("Items", [])
            
            if exclude_client_id:
                items = [item for item in items if item.get("clientID") != exclude_client_id]
            
            return len(items) > 0
        except Exception as e:
            logger.error(f"Error checking duplicate company name '{company_name}': {e}")
            return True

    def get_clients_by_filter(self, access_filter: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get clients based on access filter from policy engine"""
        filter_type = access_filter.get("type", "none")
        
        try:
            if filter_type == "all":
                return self._scan_all_clients()
            elif filter_type == "all_except_denied":
                denied_ids = access_filter.get("denied_ids", [])
                all_items = self._scan_all_clients()
                return [item for item in all_items if item.get("clientID") not in denied_ids]
            elif filter_type == "specific":
                allowed_ids = access_filter.get("allowed_ids", [])
                if not allowed_ids:
                    return []
                return self._batch_get_clients_by_ids(allowed_ids)
            elif filter_type == "creator_based":
                creator_ids = access_filter.get("creator_ids", [])
                if not creator_ids:
                    return []
                return self._get_clients_by_creators(creator_ids)
            elif filter_type == "mixed":
                allowed_ids = access_filter.get("allowed_ids", [])
                creator_ids = access_filter.get("creator_ids", [])
                denied_ids = access_filter.get("denied_ids", [])
                
                items = []
                
                # Get specific clients by ID
                if allowed_ids:
                    specific_items = self._batch_get_clients_by_ids(allowed_ids)
                    items.extend(specific_items)
                
                # Get clients by creators
                if creator_ids:
                    creator_items = self._get_clients_by_creators(creator_ids)
                    items.extend(creator_items)
                
                # Remove duplicates and denied clients
                seen_ids = set()
                unique_items = []
                for item in items:
                    client_id = item.get("clientID")
                    if client_id and client_id not in seen_ids and client_id not in denied_ids:
                        seen_ids.add(client_id)
                        unique_items.append(item)
                
                return unique_items
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error getting clients by filter: {e}")
            return []

    def _scan_all_clients(self) -> List[Dict[str, Any]]:
        """Scan all clients from the table"""
        try:
            all_items = []
            response = self.table.scan()
            all_items.extend(response.get("Items", []))
            
            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = self.table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                all_items.extend(response.get("Items", []))
            
            logger.debug(f"Scanned {len(all_items)} total clients")
            return all_items
            
        except Exception as e:
            logger.error(f"Error scanning clients: {e}")
            return []

    def _batch_get_clients_by_ids(self, ids: List[str]) -> List[Dict[str, Any]]:
        """Get multiple clients by IDs using batch get"""
        if not ids:
            return []
        
        try:
            import boto3
            ddb = boto3.resource("dynamodb")
            table_name = self.table.name
            all_items = []
            
            BATCH_SIZE = 100
            for i in range(0, len(ids), BATCH_SIZE):
                chunk_ids = ids[i:i+BATCH_SIZE]
                keys = [{"clientID": cid} for cid in chunk_ids]
                
                resp = ddb.batch_get_item(RequestItems={table_name: {"Keys": keys}})
                items = resp.get("Responses", {}).get(table_name, [])
                all_items.extend(items)
                
                # Handle unprocessed keys
                unprocessed = resp.get("UnprocessedKeys", {}).get(table_name, {}).get("Keys", [])
                if unprocessed:
                    retry_resp = ddb.batch_get_item(RequestItems={table_name: {"Keys": unprocessed}})
                    retry_items = retry_resp.get("Responses", {}).get(table_name, [])
                    all_items.extend(retry_items)
            
            logger.debug(f"Batch get retrieved {len(all_items)} items from {len(ids)} requested")
            return all_items
            
        except Exception as e:
            logger.error(f"Error in batch get clients: {e}")
            return []

    def _get_clients_by_creators(self, creator_user_ids: List[str]) -> List[Dict[str, Any]]:
        """Get all clients created by specific users"""
        if not creator_user_ids:
            return []
        
        all_clients = []
        
        for creator_id in creator_user_ids:
            try:
                # Try GSI query first (if available)
                try:
                    response = self.table.query(
                        IndexName='createdBy-index',
                        KeyConditionExpression=Key('createdBy').eq(creator_id)
                    )
                    
                    creator_clients = response.get("Items", [])
                    all_clients.extend(creator_clients)
                    
                    # Handle pagination
                    while response.get("LastEvaluatedKey"):
                        response = self.table.query(
                            IndexName='createdBy-index',
                            KeyConditionExpression=Key('createdBy').eq(creator_id),
                            ExclusiveStartKey=response["LastEvaluatedKey"]
                        )
                        additional_clients = response.get("Items", [])
                        all_clients.extend(additional_clients)
                        
                except Exception:
                    # Fallback to scan
                    logger.warning(f"GSI query failed for creator {creator_id}, falling back to scan")
                    
                    scan_response = self.table.scan(
                        FilterExpression=Attr('createdBy').eq(creator_id)
                    )
                    
                    creator_clients = scan_response.get("Items", [])
                    all_clients.extend(creator_clients)
                    
                    # Handle pagination for scan
                    while scan_response.get("LastEvaluatedKey"):
                        scan_response = self.table.scan(
                            FilterExpression=Attr('createdBy').eq(creator_id),
                            ExclusiveStartKey=scan_response["LastEvaluatedKey"]
                        )
                        additional_clients = scan_response.get("Items", [])
                        all_clients.extend(additional_clients)
                
            except Exception as e:
                logger.error(f"Error fetching clients for creator {creator_id}: {e}")
        
        logger.debug(f"Got {len(all_clients)} clients from {len(creator_user_ids)} creators")
        return all_clients