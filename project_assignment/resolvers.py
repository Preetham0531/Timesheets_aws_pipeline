import boto3
from policy_engine import register_resource_resolver

# ——— Response ——— AWS Resource
dynamodb_resource = boto3.resource("dynamodb")

# ——— Response ——— Common Owner Fields
COMMON_OWNER_FIELDS = ["createdBy", "ownerUserId", "assignedTo", "assignedBy"]

# ——— Response ——— Module Configuration
MODULE_RESOLVER_CONFIG = {
    "Tasks": {
        "table": "dev.Tasks.ddb-table",
        "primary_key": "taskID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Projects": {
        "table": "dev.Projects.ddb-table",
        "primary_key": "projectID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "TimeEntries": {
        "table": "dev.TimeEntries.ddb-table",
        "primary_key": "TimeEntryID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Approvals": {
        "table": "dev.Approvals.ddb-table",
        "primary_key": "ApprovalID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Employees": {
        "table": "dev.Employees.ddb-table",
        "primary_key": "employeeID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Users": {
        "table": "dev.Users.ddb-table",
        "primary_key": "userID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Clients": {
        "table": "dev.Clients.ddb-table",
        "primary_key": "clientID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "Contacts": {
        "table": "dev.Contacts.ddb-table",
        "primary_key": "contactID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
    "ProjectAssignments": {
        "table": "dev.ProjectAssignments.ddb-table",
        "primary_key": "assignmentID",
        "owner_fields": COMMON_OWNER_FIELDS,
    },
}


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
            "assignedBy": item.get("assignedBy"),
        }

        # ——— Response ——— Special handling for Users and Employees
        if table_name.endswith("Users.ddb-table"):
            # Self-ownership = userID
            normalized_item["createdBy"] = item.get("userID") or record_id
        elif table_name.endswith("Employees.ddb-table"):
            # Self-ownership = employeeID
            normalized_item["createdBy"] = item.get("employeeID") or record_id

        # Fallback if still missing
        if not normalized_item.get("createdBy"):
            for field in owner_fields:
                val = item.get(field)
                if val:
                    normalized_item["createdBy"] = val
                    break

        return normalized_item

    return resolver


# ——— Response ——— Register All Resolvers
for module_name, config in MODULE_RESOLVER_CONFIG.items():
    register_resource_resolver(
        module_name,
        makeResolver(config["table"], config["primary_key"], config["owner_fields"]),
    )
