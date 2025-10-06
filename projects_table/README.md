# Projects API - Modular Architecture Documentation

## Overview

This document describes the refactored, production-ready modular architecture for the Projects API Lambda function. The code has been reorganized from a single-file monolith into a clean, maintainable structure following separation of concerns principles.

## Architecture Overview

The project follows a layered architecture pattern with clear separation of responsibilities:

```
projects/
├── lambda_function.py          # Main entrypoint - routing only
├── handlers/                   # Request handling and validation layer
├── services/                   # Business logic and integrations
├── models/                     # Data access layer
├── utils/                      # Shared utilities and helpers
└── policy_engine.py           # (Unchanged) Authorization engine
```

## Folder Structure and Responsibilities

### 🚀 **lambda_function.py** (Main Entrypoint)
**Purpose**: Pure routing and request orchestration
- HTTP method routing (GET, POST, PUT, DELETE)
- Request/response parsing and validation
- CORS handling
- Error handling and standardized responses
- Authorization context extraction
- No business logic - delegates to handlers

**Key Functions**:
- `lambda_handler()` - Main AWS Lambda entrypoint
- `health_check_handler()` - Service health monitoring
- `_handle_delete_request()` - Routes DELETE operations to appropriate handlers

---

### 📋 **handlers/** (Request Processing Layer)
**Purpose**: Parse input, validate requests, coordinate with services

#### `project_handlers.py`
- `handle_create_project()` - Project creation request processing
- `handle_get_projects()` - Project retrieval and listing
- `handle_permissions_test()` - Debug endpoint for permissions testing

#### `project_crud_handlers.py`
- `handle_update_project()` - Project modification requests
- `handle_delete_project()` - Project deletion (single/batch)
- `handle_delete_projects()` - Archive/unarchive operations

**Responsibilities**:
- Request validation and sanitization
- Authorization checks (delegates to policy service)
- Input parsing and type checking
- Coordinate with services for business logic
- Format responses for clients

---

### ⚙️ **services/** (Business Logic Layer)
**Purpose**: Core business logic, integrations, and reusable workflows

#### `project_service.py`
**Core project business operations**:
- `create_project()` - Project creation with validation
- `update_project()` - Project modification logic
- `format_project_metadata()` - Add display names and formatting
- `batch_get_projects_by_ids()` - Efficient batch retrieval
- `apply_privacy_filter()` - Privacy/permissions filtering
- `check_duplicate_project_name()` - Business rule validation

#### `policy_service.py`
**Policy engine integration**:
- `can_do()` - Permission checking wrapper
- `get_allowed_record_ids()` - Scope-based access control
- `can_access_record()` - Record-level authorization
- `get_accessible_records_filter()` - Database query filters

#### `project_archive_service.py`
**Archive and lifecycle management**:
- `process_project_archive_action()` - Archive/unarchive/delete operations
- `get_entity_actions()` - Coordinate across related tables
- TTL and status management

**Key Patterns**:
- All AWS SDK calls centralized here
- Business rule validation
- Cross-entity operations
- Integration with external services

---

### 🗄️ **models/** (Data Access Layer)
**Purpose**: Database operations, table definitions, and data lookups

#### `database_models.py`
- DynamoDB table configurations
- Environment variable mapping
- Database resource initialization

#### `user_lookups.py`
- `get_user_name()` - User display name resolution
- `get_username()` - Username lookups
- `get_client_name()` - Client company name resolution  
- `get_contact_name()` - Contact name resolution

#### `validation_models.py`
- `validate_contact_and_client()` - Cross-entity validation
- Data integrity checks

**Key Patterns**:
- All database queries isolated here
- Lookup and reference data functions
- Data validation and integrity checks

---

### 🔧 **utils/** (Shared Utilities)
**Purpose**: Generic helper functions used across layers

#### `response_helpers.py`
- `build_response()` - Standardized API responses
- `get_cors_headers()` - CORS header generation

#### `date_helpers.py`
- `format_date()` - Date formatting utilities

#### `id_generators.py`
- `generate_unique_display_id()` - Unique ID generation

#### `logging_helpers.py`
- `get_logger()` - Standardized logging configuration

**Key Patterns**:
- Pure functions with no side effects
- Reusable across all layers
- No business logic or external dependencies

---

## Key Features Preserved

✅ **All Original Functionality Maintained**:
- Complete CRUD operations (Create, Read, Update, Delete)
- Policy engine integration with all authorization patterns
- Privacy controls (public/private projects with allowedUsers)
- Creator-based access patterns
- Batch operations support
- Archive/unarchive lifecycle management
- Comprehensive error handling and logging

✅ **Enhanced Capabilities**:
- Modular, maintainable code structure
- Clear separation of concerns
- Improved testability
- Better error isolation
- Enhanced logging and monitoring
- Production-ready architecture

## API Endpoints

| Method | Endpoint | Handler | Purpose |
|--------|----------|---------|---------|
| `POST` | `/` | `handle_create_project` | Create new project |
| `GET` | `/` | `handle_get_projects` | List/retrieve projects |
| `PUT` | `/` | `handle_update_project` | Update existing project |
| `DELETE` | `/` | `handle_delete_project` | Delete projects |
| `DELETE` | `/` (with action) | `handle_delete_projects` | Archive operations |
| `GET` | `/permissions-test` | `handle_permissions_test` | Debug permissions |
| `OPTIONS` | `/*` | `lambda_handler` | CORS preflight |

## Policy Engine Integration

The refactored architecture maintains full compatibility with the comprehensive policy engine:

- **Scope-based access control**: `all`, `specific`, `creator_based`, `mixed`
- **Deny-wins precedence**: Explicit denies override allows
- **Privacy filtering**: Private projects with `allowedUsers` support
- **Pattern-based authorization**: All existing patterns preserved
- **Debug endpoints**: Comprehensive permissions testing and debugging

## Error Handling

Centralized error handling with:
- Structured error responses
- Unique error IDs for tracking
- Detailed logging with stack traces
- User-friendly error messages
- Production-safe error details

## Benefits of Modular Architecture

1. **Maintainability**: Clear separation makes code easier to understand and modify
2. **Testability**: Each layer can be tested independently
3. **Scalability**: Easy to add new features without affecting existing code
4. **Reusability**: Services and utilities can be shared across different handlers
5. **Debugging**: Issues can be isolated to specific layers
6. **Team Development**: Different developers can work on different layers simultaneously

## Migration Notes

⚠️ **No Breaking Changes**: All existing API contracts maintained
⚠️ **Environment Variables**: Same environment variables required
⚠️ **Dependencies**: Same external dependencies (boto3, policy_engine)
⚠️ **Database Schema**: No database changes required

## Development Guidelines

### Adding New Features
1. **Handlers**: Add request validation and response formatting
2. **Services**: Implement business logic and external integrations
3. **Models**: Add any new database operations or lookups
4. **Utils**: Add reusable helper functions

### Testing Strategy
- **Unit Tests**: Test each service function independently
- **Integration Tests**: Test handler-to-service interactions
- **End-to-End Tests**: Test complete request flows

### Logging Standards
- Use structured logging with the provided `get_logger()` utility
- Include user IDs, operation types, and performance metrics
- Log at appropriate levels (DEBUG, INFO, WARNING, ERROR)

---

## Conclusion

This modular architecture provides a solid foundation for continued development while preserving all existing functionality. The clear separation of concerns makes the codebase more maintainable, testable, and scalable for future enhancements.

The refactoring maintains production stability while enabling better development practices and team collaboration.