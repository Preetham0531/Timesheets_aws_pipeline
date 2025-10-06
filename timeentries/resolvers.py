import os
import boto3
from policy_engine import register_resource_resolver


# ——— AWS Resource ———
dynamodb_resource = boto3.resource("dynamodb")

# ——— Common Owner Fields ———
COMMON_OWNER_FIELDS = ["createdBy", "ownerUserId", "assignedTo", "assignedBy"]

# ——— Module Configuration ———
MODULE_RESOLVER_CONFIG = {
    "Tasks": {
        "table": os.environ.get("TASKS_TABLE"),
        "primary_key": "taskID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Projects": {
        "table": os.environ.get("PROJECTS_TABLE"),
        "primary_key": "projectID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Employees": {
        "table": os.environ.get("EMPLOYEE_TABLE"),
        "primary_key": "employeeID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Users": {
        "table": os.environ.get("USERS_TABLE"),
        "primary_key": "userID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "ProjectAssignments": {
        "table": os.environ.get("PROJECT_ASSIGNMENTS_TABLE"),
        "primary_key": "assignmentID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "TimeEntries": {
        "table": os.environ.get("TIME_ENTRIES_TABLE"),
        "primary_key": "timeEntryID",
        "owner_fields": COMMON_OWNER_FIELDS,
    }
}


# ——— Resolver Factory ———
def makeResolver(table_name: str, primary_key: str, owner_fields: list[str]):
    """Create a resolver function for a specific DynamoDB table."""
    table = dynamodb_resource.Table(table_name)

    def resolver(record_id: str) -> dict:
        response = table.get_item(Key={primary_key: str(record_id)})
        item = response.get("Item") or {}

        normalized_item = {
            "id": item.get(primary_key) or record_id,
            "createdBy": item.get("createdBy"),
            "ownerUserId": item.get("ownerUserId"),
            "assignedTo": item.get("assignedTo"),
            "assignedBy": item.get("assignedBy"),
            "userID": item.get("userID"),
            "employeeID": item.get("employeeID"),
            "projectID": item.get("projectID"),
            "taskID": item.get("taskID"),
        }

        # Fallback for createdBy
        if not normalized_item.get("createdBy"):
            for field in owner_fields:
                val = item.get(field)
                if val:
                    normalized_item["createdBy"] = val
                    break

        return normalized_item

    return resolver


# ——— Register All Resolvers ———
for module_name, config in MODULE_RESOLVER_CONFIG.items():
    register_resource_resolver(
        module_name,
        makeResolver(config["table"], config["primary_key"], config["owner_fields"]),
    )
