# IAM Roles Management System - Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Module Structure](#module-structure)
4. [Core Functionality](#core-functionality)
5. [API Endpoints](#api-endpoints)
6. [Policy Engine Integration](#policy-engine-integration)
7. [Development Guide](#development-guide)

---

## Overview

The IAM Roles Management System is a comprehensive AWS Lambda-based service for managing role-based access control (RBAC) with support for:

- **Global Role Management**: Create, read, update, and delete roles
- **User-Specific Customization**: Override role permissions for individual users
- **Fine-Grained Permissions**: Module-level and action-level access control
- **Selective Access**: Support for selected IDs, creators, and denial patterns
- **Policy Engine Integration**: Advanced permission evaluation with deny-wins logic

### Key Features

✅ **Production-Ready**: Clean separation of concerns, proper error handling  
✅ **Modular Design**: Easy to extend and maintain  
✅ **Type Safety**: Clear data flow and interfaces  
✅ **Performance Optimized**: Efficient database queries and caching  
✅ **Well-Documented**: Comprehensive inline documentation  

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Lambda Function Entry                     │
│                   (lambda_function.py)                       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                      Handlers Layer                          │
│  • Request validation                                        │
│  • Parameter extraction                                      │
│  • Routing to services                                       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                     Services Layer                           │
│  • Business logic                                            │
│  • Policy evaluation                                         │
│  • Override merging                                          │
│  • AWS SDK calls                                             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                      Models Layer                            │
│  • Database operations (DynamoDB)                            │
│  • Query optimization                                        │
│  • Data transformation                                       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                       Utils Layer                            │
│  • Response formatting                                       │
│  • Validation helpers                                        │
│  • Time utilities                                            │
│  • JSON serialization                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### 📁 Project Organization

```
iam_roles/
├── lambda_function.py              # Entry point
├── config.py                       # Configuration
├── logging_config.py               # Logging setup
│
├── handlers/                       # Request handlers
│   ├── __init__.py
│   └── role_handler.py            # HTTP method routing
│
├── services/                       # Business logic
│   ├── __init__.py
│   ├── role_creation_service.py   # Role creation
│   ├── role_retrieval_service.py  # Role retrieval
│   ├── role_update_service.py     # Role updates
│   ├── role_deletion_service.py   # Role deletion
│   ├── user_customization_service.py  # User overrides
│   └── user_role_view_service.py  # User-specific views
│
├── models/                         # Data access layer
│   ├── __init__.py
│   ├── database.py                # DB connections
│   ├── role_repository.py         # Role queries
│   ├── assignment_repository.py   # User assignments
│   ├── employee_repository.py     # Employee data
│   └── sequence_repository.py     # ID generation
│
├── utils/                          # Helper utilities
│   ├── __init__.py
│   ├── response_utils.py          # API responses
│   ├── validation_utils.py        # Input validation
│   ├── time_utils.py              # Date/time helpers
│   ├── token_utils.py             # Pagination tokens
│   └── json_utils.py              # JSON serialization
│
├── policy_engine.py               # Policy evaluation (DO NOT MODIFY)
├── policy_integration.py          # Policy engine interface
├── policies.py                    # Policy utilities
├── formatting.py                  # Response formatting
├── overrides.py                   # User override logic
└── docs/                          # Documentation
    └── OVERVIEW.md                # This file
```

---

## Core Functionality

### 1. Role Creation

**Service**: `role_creation_service.py`

Creates new roles with policies defining permissions across modules.

**Flow**:
1. Validate user has `IAM.create` permission
2. Parse and validate request body
3. Check for role name conflicts
4. Normalize policies
5. Generate unique identifiers
6. Store in DynamoDB

**Example Request**:
```json
{
  "role": "project_manager",
  "displayName": "Project Manager",
  "description": "Manages projects and teams",
  "modules": {
    "Projects": {
      "allow": {
        "view": ["all"],
        "create": ["self"],
        "modify": ["selected_ids"],
        "delete": ["self"]
      },
      "SelectedIds": {
        "modify": ["proj-123", "proj-456"]
      }
    }
  }
}
```

### 2. Role Retrieval

**Service**: `role_retrieval_service.py`

Retrieves roles based on various criteria with permission filtering.

**Endpoints**:
- `GET /roles` - List all accessible roles
- `GET /roles?rid=<id>` - Get specific role by ID
- `GET /roles?role=<name>` - Get specific role by name
- `GET /roles?rid=<id>&user_id=<uid>` - Get user-specific view with overrides
- `GET /roles?rid=<id>&get=users` - List users with this role

**Query Parameters**:
- `status`: Filter by status (active/inactive)
- `view`: Response format (full/summary)
- `limit`: Pagination limit (default: 50)
- `nextToken`: Pagination continuation
- `includePermissions`: Include resolved permissions

### 3. Role Update

**Services**: `role_update_service.py`, `user_customization_service.py`

Updates roles globally or creates user-specific overrides.

**Global Update** (without user_id):
```json
PUT /roles
{
  "rid": "role-123",
  "displayName": "Updated Name",
  "modules": {
    "Projects": {
      "allow": {
        "view": ["all"]
      }
    }
  }
}
```

**User-Specific Customization** (with user_id):
```json
PUT /roles?user_id=user-456
{
  "rid": "role-123",
  "baseRole": "project_manager",
  "modules": {
    "Projects": {
      "allow": {
        "modify": ["selected_ids"]
      },
      "SelectedIds": {
        "modify": ["proj-789"]
      }
    }
  }
}
```

### 4. Role Deletion

**Service**: `role_deletion_service.py`

Supports soft delete (status change) and hard delete (cascade).

**Soft Delete** (default):
- Changes role status to "inactive"
- Preserves data for audit
- Idempotent operation

**Hard Delete** (cascade=true):
- Permanently removes role
- Requires explicit confirmation
- Blocked for system roles

**Query Parameters**:
- `cascade`: Enable hard delete (default: false)
- `dryRun`: Preview without executing (default: false)
- `idempotent`: Allow deletion of non-existent roles (default: true)

---

## API Endpoints

### OPTIONS /roles
**Purpose**: CORS preflight and API discovery

**Response**:
```json
{
  "ok": true,
  "supportedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  "policyEngineEnabled": true,
  "supportsUserCustomization": true,
  "operationTypes": {
    "global": "Operations without user_id affect global roles",
    "userCustomization": "Operations with user_id create user overrides"
  }
}
```

### POST /roles
**Purpose**: Create new role

**Authentication**: Required  
**Authorization**: `IAM.create` permission  
**Body**: Role definition (see examples above)

**Success Response**: `201 Created`
```json
{
  "message": "Role created successfully",
  "role": {
    "rid": "550e8400-e29b-41d4-a716-446655440000",
    "role": "project_manager",
    "displayId": "ROL-00123",
    "displayName": "Project Manager",
    "status": "active",
    "policies": { ... },
    "createdAt": "2025-10-05T10:30:00Z",
    "createdById": "user-123",
    "createdByName": "John Doe"
  }
}
```

### GET /roles
**Purpose**: List or retrieve roles

**Authentication**: Required  
**Authorization**: `IAM.view` permission

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| rid | string | Filter by role ID |
| role | string | Filter by role name |
| user_id | string | Get user-specific view |
| status | string | Filter by status |
| view | string | Response format (full/summary) |
| limit | number | Pagination limit (1-200) |
| nextToken | string | Pagination token |
| includePermissions | boolean | Include resolved permissions |
| get | string | Special operations (e.g., "users") |

**Success Response**: `200 OK`
```json
{
  "ok": true,
  "roles": [ ... ],
  "totalCount": 15,
  "scope": "all",
  "activeScopes": ["all"],
  "policyEngineAvailable": true,
  "filterType": "all",
  "pattern": "all"
}
```

### PUT /roles
**Purpose**: Update role or create user override

**Authentication**: Required  
**Authorization**: `IAM.modify` permission (or self for user customization)

**Global Update** (no user_id):
- Modifies role definition
- Affects all users with this role

**User Customization** (with user_id):
- Creates user-specific override
- Merges with base role at runtime

**Success Response**: `200 OK`
```json
{
  "ok": true,
  "message": "Role updated successfully",
  "updateType": "global",
  "updatedRid": "role-123",
  "updatedRole": "project_manager",
  "updatedAt": "2025-10-05T11:00:00Z"
}
```

### DELETE /roles
**Purpose**: Delete or deactivate role

**Authentication**: Required  
**Authorization**: `IAM.delete` permission

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| rid | string | *required* | Role ID to delete |
| cascade | boolean | false | Enable hard delete |
| dryRun | boolean | false | Preview without executing |
| idempotent | boolean | true | Allow deletion of non-existent roles |

**Success Response**: `200 OK`
```json
{
  "ok": true,
  "rid": "role-123",
  "roleName": "project_manager",
  "status": "inactive"
}
```

---

## Policy Engine Integration

The system integrates with a comprehensive policy engine (`policy_engine.py`) for advanced permission evaluation.

### Permission Model

**Scope Types**:
- `all`: Access to all records
- `self`: Access to own records
- `selected`: Access to specific record IDs
- `selected_by_creator`: Access to records by specific creators
- `deny`: Explicit denial (highest precedence)

**Policy Structure**:
```json
{
  "ModuleName": {
    "allow": {
      "action": ["scope1", "scope2"]
    },
    "deny": {
      "action": ["scope"]
    },
    "SelectedIds": {
      "action": ["id1", "id2"]
    },
    "DeniedIds": {
      "action": ["id3", "id4"]
    },
    "SelectedCreators": {
      "action": ["user1", "user2"]
    },
    "DeniedCreators": {
      "action": ["user3", "user4"]
    }
  }
}
```

### Evaluation Logic

1. **Gather Rules**: Collect from roles + overrides
2. **Apply Precedence**: Overrides > Roles
3. **Evaluate Scopes**: Expand scope types to record IDs
4. **Apply Deny-Wins**: Denials override allows
5. **Return Decision**: ALLOW/DENY with record IDs

### Key Functions

```python
# Check permission for an action
can_do(user_id, module, action) -> bool

# Get allowed record IDs for an action
get_allowed_record_ids(user_id, module, action) -> dict

# Check access to specific record
can_access_record(user_id, module, action, record_id) -> bool

# Get filter for database queries
get_accessible_records_filter(user_id, module, action) -> dict
```

---

## Development Guide

### Adding New Functionality

#### 1. Add a New Endpoint

**Step 1**: Create service function in `services/`
```python
# services/new_feature_service.py
from logging_config import create_logger
from utils import build_response

logger = create_logger("services.new_feature")

def handle_new_feature(event, caller_id):
    """Handle new feature logic."""
    try:
        # Business logic here
        return build_response(event=event, data={"ok": True}, status=200)
    except Exception as e:
        logger.exception("New feature failed")
        return build_response(event=event, error="Internal server error", status=500)
```

**Step 2**: Add to handlers
```python
# handlers/role_handler.py
from services import handle_new_feature

def handle_get_request(event, caller_id):
    qs = event.get("queryStringParameters") or {}
    if qs.get("feature") == "new":
        return handle_new_feature(event, caller_id)
    # ... existing logic
```

**Step 3**: Export from service package
```python
# services/__init__.py
from .new_feature_service import handle_new_feature

__all__ = [
    # ... existing exports
    'handle_new_feature'
]
```

#### 2. Add Database Operations

**Step 1**: Create repository function
```python
# models/new_repository.py
from .database import ROLES_TBL
from boto3.dynamodb.conditions import Key

def query_new_data(param):
    """Query new data from database."""
    response = ROLES_TBL.query(
        KeyConditionExpression=Key("pk").eq(param)
    )
    return response.get("Items", [])
```

**Step 2**: Export from models package
```python
# models/__init__.py
from .new_repository import query_new_data

__all__ = [
    # ... existing exports
    'query_new_data'
]
```

#### 3. Add Utility Functions

```python
# utils/new_utils.py
def new_utility_function(input):
    """New utility function."""
    return processed_output
```

### Testing Strategy

#### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Cover edge cases and error handling

#### Integration Tests
- Test complete request flows
- Use real database (test environment)
- Verify authorization logic

#### Load Tests
- Simulate concurrent requests
- Monitor Lambda performance
- Optimize cold start times

### Error Handling Best Practices

1. **Use try-except blocks** in all service functions
2. **Log exceptions** with context
3. **Return meaningful error messages** to clients
4. **Use appropriate HTTP status codes**
5. **Never expose internal details** in errors

### Performance Optimization

1. **Minimize DynamoDB queries**: Use batch operations
2. **Cache frequently accessed data**: Role definitions
3. **Use pagination**: For list operations
4. **Optimize JSON serialization**: Use custom encoders
5. **Monitor Lambda metrics**: Execution time, memory

### Security Considerations

1. **Validate all inputs**: Never trust client data
2. **Check authorization**: For every operation
3. **Sanitize error messages**: No sensitive data exposure
4. **Use IAM roles**: For AWS resource access
5. **Encrypt sensitive data**: At rest and in transit

---

## Troubleshooting

### Common Issues

**Issue**: "Not authorized" errors
- **Cause**: Policy engine denying access
- **Solution**: Check user's role assignments and policies
- **Debug**: Use `?includePermissions=true&debug=true`

**Issue**: Role not found
- **Cause**: Incorrect RID or role name
- **Solution**: Verify identifier spelling and case
- **Debug**: Check DynamoDB table directly

**Issue**: User override not applying
- **Cause**: No base role assignment
- **Solution**: Ensure user has base role before customizing
- **Debug**: Check user assignments in UserGrants table

### Debugging Tools

**Enable Debug Logging**:
```python
# Set environment variable
LOG_LEVEL=DEBUG

# Or in code
import logging
logging.getLogger("roles").setLevel(logging.DEBUG)
```

**Get Permission Debug Info**:
```
GET /roles?rid=<role-id>&debug=true&includePermissions=true
```

**Check Policy Engine Status**:
```
OPTIONS /roles
```

---

## Appendix

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| ROLES_TABLE | DynamoDB roles table | dev.roles_t.ddb-table |
| USER_GRANTS_TABLE | User assignments table | dev.UserGrants.ddb-table |
| SEQUENCES_TABLE | Sequence generator table | dev.Sequences.ddb-table |
| EMPLOYEES_TABLE | Employee data table | dev.Employees.ddb-table |
| DEFAULT_PAGE_SIZE | Pagination default | 50 |
| BATCH_SIZE | DynamoDB batch size | 100 |
| POLICY_ENGINE_LOG_LEVEL | Policy engine logging | INFO |

### Database Schema

**Roles Table** (`dev.roles_t.ddb-table`):
- Primary Key: `rid` (String)
- GSI: `role-rid-index` on `role` field
- Attributes: rid, role, displayName, note, Policies, Status, createdAt, etc.

**User Grants Table** (`dev.UserGrants.ddb-table`):
- Primary Key: `userID` (String), `ovID` (String)
- GSI: `role-index` on `role` field
- Attributes: userID, ovID, role, module, contextType, Allow, Deny, etc.

### API Response Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful operation |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Missing authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 405 | Method Not Allowed | Unsupported HTTP method |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Unexpected error |

---

## Support and Maintenance

For questions or issues:
1. Check this documentation
2. Review inline code comments
3. Enable debug logging
4. Consult policy engine documentation

**Last Updated**: October 5, 2025  
**Version**: 2.0.0  
**Architecture**: Production-Ready Modular Design
