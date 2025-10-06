# Client Management System

## Overview

This is a comprehensive client management system built for AWS Lambda with API Gateway integration. The system provides full CRUD operations for client management with advanced policy-based authorization, privacy controls, and project management integration.

## Architecture

The system follows a modular, production-ready architecture with clear separation of concerns:

```
├── lambda_function.py          # Main entrypoint and request routing
├── handlers/                   # Request handlers (API Gateway integration)
│   └── client_handler.py       # Client request processing and validation
├── services/                   # Business logic and workflows
│   ├── client_service.py       # Client business operations
│   └── policy_service.py       # Authorization and policy engine integration
├── models/                     # Data access layer
│   ├── client_model.py         # Client database operations
│   └── project_model.py        # Project database operations
├── utils.py                    # Shared utilities and helpers
└── policy_engine.py           # Advanced policy engine (existing)
```

## Key Features

### Client Management
- **Create clients** with comprehensive validation
- **Retrieve clients** with flexible filtering and permissions
- **Update clients** with field-level validation
- **Delete clients** with batch operations support
- **Privacy controls** with allowedUsers lists
- **Company name uniqueness** validation

### Authorization & Security
- **Policy engine integration** with comprehensive access control
- **Creator-based access patterns** for fine-grained permissions
- **Privacy filtering** for sensitive client data
- **Role-based permissions** with override support
- **Audit logging** with user tracking

### Advanced Features
- **Project integration** with client-project relationships
- **Batch operations** for efficient bulk processing
- **Debug endpoints** for troubleshooting permissions
- **CORS support** for multiple origins
- **Comprehensive error handling** with detailed responses

## Module Documentation

### lambda_function.py
**Purpose:** Main Lambda entrypoint that routes requests to appropriate handlers.

**Key Functions:**
- `lambda_handler()` - Main entry point that handles CORS, authentication, and routing
- Validates user authorization context
- Routes HTTP methods (GET, POST, PUT, DELETE) to appropriate handlers
- Handles CORS preflight requests

### handlers/client_handler.py
**Purpose:** API Gateway request handlers that parse input and delegate to services.

**Key Functions:**
- `handle_create()` - Processes client creation requests
- `handle_get()` - Handles client retrieval with filtering
- `handle_update()` - Manages client update operations
- `handle_delete()` - Processes client deletion requests
- `handle_permissions_test()` - Debug endpoint for permission testing

### services/client_service.py
**Purpose:** Core business logic for client operations and workflows.

**Key Functions:**
- `create_client()` - Complete client creation workflow with validation
- `get_clients()` - Client retrieval with policy filtering and privacy controls
- `update_client()` - Client update operations with authorization checks
- `delete_clients()` - Batch client deletion with validation
- `_apply_privacy_filter()` - Privacy-based access control
- `_validate_create_fields()` - Input validation for client creation

### services/policy_service.py
**Purpose:** Authorization service that integrates with the policy engine.

**Key Functions:**
- `can_create_client()` - Check client creation permissions
- `can_view_client()` - Validate client viewing permissions
- `can_modify_client()` - Authorize client modifications
- `can_delete_client()` - Check deletion permissions
- `get_accessible_records_filter()` - Get filtering criteria for database queries
- `build_authorization_error()` - Generate detailed authorization error responses

### models/client_model.py
**Purpose:** Data access layer for client database operations.

**Key Functions:**
- `create_client()` - Insert new client records
- `get_client_by_id()` - Retrieve specific client by ID
- `update_client()` - Update existing client records
- `delete_client()` - Remove client records
- `check_duplicate_company_name()` - Validate company name uniqueness
- `get_clients_by_filter()` - Query clients based on policy filters
- `_batch_get_clients_by_ids()` - Efficient batch retrieval
- `_get_clients_by_creators()` - Get clients by creator user IDs

### models/project_model.py
**Purpose:** Data access layer for project-related operations.

**Key Functions:**
- `get_client_projects_with_policy()` - Get projects for a client with authorization
- `_apply_projects_policy_filter()` - Apply policy filtering to project lists

### utils.py
**Purpose:** Shared utilities and helper functions.

**Key Functions:**
- `build_response()` - Standardized API response builder
- `get_cors_headers()` - CORS header management
- `get_username()` - User name resolution
- `generate_unique_display_id()` - Unique ID generation
- `format_date()` - Date formatting utilities

### policy_engine.py
**Purpose:** Advanced policy engine for fine-grained access control.

**Key Features:**
- Creator-based access patterns
- Comprehensive deny-wins logic
- Override precedence handling
- Pattern-based filtering (all, specific, creator-based, mixed)
- Debug and troubleshooting capabilities

## API Endpoints

### POST /clients
Create a new client with comprehensive validation and authorization.

**Request Body:**
```json
{
  "companyName": "Example Corp",
  "email": "contact@example.com", 
  "phone": "+1-555-0123",
  "website": "https://example.com",
  "status": "Active",
  "private": false,
  "allowedUsers": [],
  "address": {
    "street1": "123 Main St",
    "city": "Anytown",
    "state": "NY",
    "zipCode": "12345"
  }
}
```

### GET /clients
Retrieve clients with filtering and permissions.

**Query Parameters:**
- `clientID` - Get specific client
- `view` - View type (full/summary)
- `includePermissions` - Include permission metadata
- `includeProjects` - Include related projects
- `projectsOnly` - Get only projects for client
- `debug` - Debug mode with permission details

### PUT /clients
Update an existing client with field-level validation.

**Request Body:**
```json
{
  "clientID": "uuid-here",
  "companyName": "Updated Corp",
  "private": true,
  "allowedUsers": ["user1", "user2"]
}
```

### DELETE /clients
Delete one or more clients with authorization checks.

**Request Body:**
```json
{
  "clientIDs": ["uuid1", "uuid2", "uuid3"]
}
```

## Privacy Controls

The system includes comprehensive privacy controls:

- **Public clients** (default) - Accessible based on policy engine rules
- **Private clients** - Only accessible to users in `allowedUsers` list
- **Privacy filtering** - Applied after policy engine filtering
- **Backward compatibility** - Existing clients remain public by default

## Error Handling

The system provides detailed error responses with:

- **Validation errors** - Field-level validation with specific messages
- **Authorization errors** - Detailed permission context and suggestions
- **Business logic errors** - Clear error messages for business rules
- **System errors** - Standardized error responses with logging

## Database Schema

### Clients Table
- `clientID` (PK) - Unique identifier
- `displayID` - Human-readable ID (e.g., CLI-00001)
- `companyName` - Company name (unique constraint)
- `email` - Contact email
- `phone` - Contact phone
- `website` - Company website
- `status` - Client status (Active/Inactive)
- `address` - Structured address object
- `private` - Privacy flag
- `allowedUsers` - List of authorized user IDs
- `createdBy` - Creator user ID
- `createdAt` - Creation timestamp
- `updatedBy` - Last updater user ID
- `updatedAt` - Last update timestamp

### Global Secondary Indexes
- `createdBy-index` - For creator-based queries
- `clientID-index` (Projects) - For client-project relationships

## Performance Optimizations

- **Batch operations** for bulk processing
- **GSI queries** for efficient filtering
- **Pagination support** for large datasets
- **Policy caching** for authorization decisions
- **Selective field updates** to minimize database writes

## Monitoring and Debugging

The system includes comprehensive logging and debugging features:

- **Structured logging** with correlation IDs
- **Permission debugging** endpoints
- **Performance metrics** tracking
- **Error correlation** with request context
- **Policy decision audit trails**

## Security Considerations

- **Input validation** on all endpoints
- **SQL injection prevention** through parameterized queries
- **Access control** through policy engine integration
- **Audit logging** for all operations
- **Privacy controls** for sensitive data
- **CORS policies** for cross-origin security

## Deployment

The system is designed for AWS Lambda deployment with:

- **Environment variables** for table names
- **IAM roles** for DynamoDB access
- **API Gateway integration** for HTTP endpoints
- **CloudWatch logging** for monitoring
- **VPC configuration** if required

## Future Enhancements

Potential areas for expansion:

- **Contact management** integration
- **Document attachment** support
- **Advanced search** capabilities
- **Reporting and analytics** features
- **Integration APIs** for external systems
- **Mobile app support** with offline capabilities