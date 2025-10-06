import os
import boto3
from policy_engine import register_resource_resolver

# Initialize DynamoDB resource
dynamodb_resource = boto3.resource("dynamodb")

# Common owner-related fields
COMMON_OWNER_FIELDS = ["createdBy", "ownerUserId", "assignedTo"]

# Table names from environment
EMPLOYEES_TABLE = os.environ.get("EMPLOYEES_TABLE")
USERS_TABLE = os.environ.get("USERS_TABLE")

# Resolver factory
def makeResolver(table_name: str, primary_key: str, owner_fields: list[str]):
    """Create a resolver function for a specific DynamoDB table."""

    table = dynamodb_resource.Table(table_name)

    def resolver(record_id: str) -> dict:
        """Fetch and normalize record ownership data from DynamoDB."""
        response = table.get_item(Key={primary_key: str(record_id)})
        item = response.get("Item") or {}

        normalized_item = {
            "id": item.get(primary_key) or record_id,
            "createdBy": item.get("createdBy"),
            "ownerUserId": item.get("ownerUserId"),
            "assignedTo": item.get("assignedTo"),
        }

        # Fallback: populate createdBy if missing
        if normalized_item["createdBy"] is None:
            for field in owner_fields:
                field_value = item.get(field)
                if field_value:
                    normalized_item["createdBy"] = field_value
                    break

        return normalized_item

    return resolver


# Register only Employees and Users resolvers
if EMPLOYEES_TABLE:
    register_resource_resolver(
        "Employees",
        makeResolver(EMPLOYEES_TABLE, "employeeID", COMMON_OWNER_FIELDS)
    )

if USERS_TABLE:
    register_resource_resolver(
        "Users",
        makeResolver(USERS_TABLE, "userID", COMMON_OWNER_FIELDS)
    )
