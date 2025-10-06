# Approval System - Modular Architecture Documentation

## Overview

This is a production-ready AWS Lambda-based approval system for timesheet entries with comprehensive policy engine integration. The system has been refactored from a monolithic structure into a clean, modular architecture with clear separation of concerns.

## Key Features

- **Comprehensive Authorization**: Policy engine integration with role-based access control
- **Workflow Management**: Complete approval lifecycle (raise, approve, reject)
- **Email Notifications**: Automated notifications for approval events  
- **Self-Approval Prevention**: Business rule preventing users from approving their own requests
- **Project-Scoped Access**: Users can only raise approvals for entries they own or projects they created
- **Audit Logging**: Comprehensive logging for debugging and compliance

## Architecture Overview

The system follows a layered architecture pattern:

```
lambda_function.py (Entry Point)
├── handlers/ (Request Processing)
│   └── approval_handlers.py
├── services/ (Business Logic)  
│   ├── approval_service.py
│   ├── policy_service.py
│   └── email_service.py
├── models/ (Data Access)
│   ├── approval_model.py
│   ├── time_entry_model.py  
│   ├── project_model.py
│   └── assignment_model.py
├── utils.py (Shared Utilities)
└── policy_engine.py (Authorization Framework)
```

## Folder Structure

### `lambda_function.py`
**Purpose**: Main Lambda entrypoint and request router
- Routes incoming HTTP requests to appropriate handlers
- Handles CORS preflight requests
- Extracts and validates authorization context
- Provides centralized error handling and logging
- Adds execution metadata to successful responses

### `handlers/`
**Purpose**: Request validation and response formatting
- **`approval_handlers.py`**: HTTP request handlers for approval operations
  - `handle_raise_approval()`: Processes approval raise requests
  - `handle_update_approval()`: Processes approve/reject requests  
  - `handle_get_approval_summary()`: Processes summary requests
  - `handle_permissions_test()`: Debug endpoint for testing permissions

### `services/`
**Purpose**: Business logic and external integrations
- **`approval_service.py`**: Core business logic for approval operations
  - Authorization validation using policy engine
  - Business rule enforcement (self-approval prevention, ownership checks)
  - Email notification coordination
  - Data aggregation and filtering
- **`policy_service.py`**: Policy engine integration wrapper
  - Provides consistent interface to policy engine
  - Implements fallback behavior when policy engine unavailable
  - Handles permission debugging and testing
- **`email_service.py`**: Email notification handling
  - Sends approval raised notifications to approvers
  - Sends approval decision notifications to requesters
  - Handles email template formatting

### `models/`
**Purpose**: Data access layer and database operations
- **`approval_model.py`**: CRUD operations for approval records
  - Create, read, update approval records
  - Query by ID, time entry, status
- **`time_entry_model.py`**: Operations for time entry records
  - Update approval status on time entries
  - Query time entries by ID
- **`project_model.py`**: Project-related data access
  - Get project creator information
- **`assignment_model.py`**: Project assignment operations
  - Get users assigned to projects
  - Get projects assigned to users

### `utils.py`
**Purpose**: Shared utilities and helper functions
- Response building with CORS headers
- User and project name resolution
- Date formatting and validation
- Email sending utilities
- Task name resolution with fallback logic

### `policy_engine.py`
**Purpose**: Advanced authorization framework (unchanged)
- Role-based access control
- Dynamic policy evaluation
- Record-level permissions
- Comprehensive audit capabilities

## API Endpoints

### GET - Approval Summary
**Endpoint**: `GET /?action=summary&startDate=YYYY-MM-DD&endDate=YYYY-MM-DD`
**Purpose**: Get approval statistics and detailed breakdowns
**Authorization**: Requires `Approvals.view` permission
**Response**: 
```json
{
  "summary": {
    "pending": 5,
    "approved": 12,
    "rejected": 2,
    "approvedToday": 3
  },
  "weekly": [...],
  "daily": [...]
}
```

### POST - Raise Approvals  
**Endpoint**: `POST /` 
**Body**: 
```json
{
  "action": "raise",
  "timeEntryIDs": ["entry1", "entry2"]
}
```
**Purpose**: Create new approval requests
**Business Rules**: 
- Only entry owner or project creator can raise approvals
- Prevents duplicate pending approvals
- Sends notifications to users with `approve_reject` permission
**Authorization**: Policy engine checks `TimeEntries.view` per entry

### POST - Update Approvals
**Endpoint**: `POST /`
**Body**:
```json
{
  "action": "update", 
  "approvalIDs": ["approval1"],
  "status": "Approved|Rejected",
  "comments": "Optional comments"
}
```
**Purpose**: Approve or reject approval requests
**Business Rules**:
- Requires `Approvals.approve_reject` permission
- **Self-approval prevention**: Users cannot approve their own requests
- Record-level access control per approval
- Sends decision notifications if user has `email` permission
**Authorization**: Policy engine enforces comprehensive access control

### GET - Permissions Test (Debug)
**Endpoint**: `GET /permissions-test?testUserId=user&approvalID=id`
**Purpose**: Debug endpoint for testing permissions
**Response**: Detailed permission breakdown for debugging

## Business Rules

### 1. **Self-Approval Prevention**
- Users cannot approve requests they raised themselves
- Checked via `RequestRaisedBy` field comparison
- Takes precedence over all policy permissions
- Returns specific error messages for blocked attempts

### 2. **Raise Permission Logic**
- Entry owner can always raise approval for their entries
- Project creator can raise approval for any entry in their project
- Policy engine validates view access to time entries
- Prevents duplicate pending approvals per time entry

### 3. **Policy Engine Integration**
- **Module-level actions**: `view`, `raise`, `approve_reject`, `email`
- **Record-level filtering**: Specific approval/entry access control
- **Pattern support**: `all`, `specific`, `all_except_denied`, `deny_only`  
- **Override precedence**: User overrides take precedence over role policies

### 4. **Email Notifications**
- Approval raised: Notifies users with `approve_reject` permission on project
- Approval decision: Notifies entry owner of approve/reject decision
- Requires `Approvals.email` permission to send notifications
- Rich HTML email templates with approval details

## Error Handling

### Status Code Logic
- **200**: All operations successful
- **207**: Partial success (some requests succeeded, some failed)  
- **400**: Bad request (validation errors, malformed input)
- **403**: Forbidden (authorization failures, self-approval attempts)
- **401**: Unauthorized (missing/invalid auth context)
- **500**: Internal server error (unexpected exceptions)

### Error Response Format
```json
{
  "error": "Error message",
  "results": {...},
  "statistics": {
    "total": 3,
    "successful": 1, 
    "failed": 2,
    "authorizationErrors": 1
  },
  "warnings": ["Self-approval attempts blocked"]
}
```

## Policy Engine Integration

### Access Patterns
- **`all`**: User has access to all records in module
- **`specific`**: User has access to specific record IDs only
- **`all_except_denied`**: User has access to all except specific denied IDs
- **`none`**: User has no access

### Policy Actions
- **`Approvals.view`**: Can view approval requests and summaries
- **`Approvals.raise`**: Can create new approval requests  
- **`Approvals.approve_reject`**: Can approve or reject requests
- **`Approvals.email`**: Can send email notifications
- **`TimeEntries.view`**: Can view time entry details (checked per entry)

### Authorization Flow
1. **Module-level check**: Verify user can perform action on module
2. **Record-level filtering**: Apply policy-based filtering to results
3. **Business rule validation**: Enforce self-approval prevention
4. **Final authorization**: Combine policy + business rules for decision

## Database Schema

### Approval Records (APPROVALS_TABLE)
- **Primary Key**: `ApprovalID` + `ManagerID`
- **GSI**: `ApprovalID-index`, `TimeEntryID-index`, `ApprovalStatus-index`
- **Key Fields**: `RequestRaisedBy`, `UserID`, `projectID`, `ApprovalStatus`

### Time Entry Records (TIME_ENTRIES_TABLE)  
- **Primary Key**: `TimeEntryID`
- **GSI**: `TimeEntryID-index`
- **Key Fields**: `UserID`, `projectID`, `RegularHours`, `OvertimeHours`

### Project Assignments (PROJECT_ASSIGNMENTS_TABLE)
- **GSI**: `GSI_UserID`, `ProjectAssignments-index`
- **Purpose**: Link users to projects for permission scoping

## Development & Debugging

### Logging Levels
- **INFO**: Key business events (approval created, decision made)
- **WARNING**: Authorization failures, policy engine issues  
- **ERROR**: Database errors, email failures, unexpected exceptions
- **DEBUG**: Detailed flow information (removed verbose logs in production)

### Debug Endpoints
- **`/permissions-test`**: Test user permissions against specific approvals
- **Query parameter `debug=true`**: Enable debug mode for any GET request

### Monitoring Points
- Policy engine availability and response times
- Email delivery success/failure rates  
- Authorization decision patterns
- Self-approval attempt frequency

## Production Considerations

### Performance
- Batch loading of approval records to minimize DynamoDB calls
- Policy engine caching (5-minute TTL)
- Efficient GSI usage for common query patterns
- Connection pooling for database resources

### Security
- Comprehensive authorization at multiple layers
- Self-approval prevention as business-critical rule
- Input validation and sanitization
- Audit logging for compliance

### Scalability  
- Stateless Lambda functions
- DynamoDB auto-scaling
- Policy engine horizontal scaling
- Email service rate limiting

### Error Recovery
- Graceful policy engine fallback
- Partial success handling for batch operations
- Comprehensive error logging with correlation IDs
- Email delivery retry mechanisms

## Testing Strategy

The modular architecture enables comprehensive testing:

### Unit Tests
- **Services**: Mock model dependencies, test business logic
- **Models**: Test database operations with local DynamoDB
- **Handlers**: Mock service dependencies, test request/response handling

### Integration Tests  
- **End-to-end approval workflows**
- **Policy engine integration scenarios**
- **Email notification delivery**
- **Database consistency checks**

### Load Testing
- **Concurrent approval processing**
- **Policy engine performance under load**
- **Database throughput limits**
- **Lambda cold start optimization**

---

This modular architecture provides a maintainable, testable, and scalable foundation for the approval system while preserving all existing functionality and business rules.