# Contacts API - Module Overview

## Architecture Overview

This Contacts API module has been refactored into a clean, modular architecture that separates concerns and improves maintainability. The code follows production-ready patterns with clear separation of responsibilities.

## Folder Structure

```
contacts-api/
├── lambda_function.py          # Entry point - routing only
├── handlers/                   # Request handlers
│   └── contact_handler.py      # Parse input, validate, delegate to services
├── services/                   # Business logic layer
│   ├── contact_service.py      # Core contact operations
│   ├── authorization_service.py # Policy engine integration
│   └── privacy_service.py      # Privacy and user access management
├── models/                     # Data access layer
│   ├── contact_model.py        # Contact database operations
│   ├── project_model.py        # Project database operations
│   └── user_model.py           # User database operations
├── utils.py                    # Shared utilities (unchanged)
├── policy_engine.py           # Policy engine (unchanged)
└── docs/
    └── README.md              # This documentation
```

## Layer Responsibilities

### 1. Entry Point (`lambda_function.py`)
- **Purpose**: AWS Lambda entry point and request routing
- **Responsibilities**:
  - Parse incoming requests
  - Extract authorization context
  - Route to appropriate handlers
  - Handle CORS and error responses
  - Add execution metadata

### 2. Handlers (`handlers/`)
- **Purpose**: Request processing and input validation
- **Responsibilities**:
  - Parse and validate request input
  - Coordinate between services
  - Build response objects
  - Handle request-specific logic (debug endpoints, permissions testing)

### 3. Services (`services/`)
- **Purpose**: Business logic and workflow orchestration
- **Responsibilities**:
  - **ContactService**: Core CRUD operations, privacy integration, list filtering
  - **AuthorizationService**: Policy engine integration, permission checks
  - **PrivacyService**: Private contact handling, user validation

### 4. Models (`models/`)
- **Purpose**: Data access layer
- **Responsibilities**:
  - Database operations (CRUD)
  - Query optimization
  - Data validation at storage level
  - Handle database-specific logic (pagination, batching)

## Key Features

### Authorization & Security
- **Policy Engine Integration**: Comprehensive authorization using policy engine
- **Creator-based Access**: Support for creator-based permission patterns
- **Record-level Permissions**: Individual contact access control
- **Batch Operations**: Efficient bulk operations with authorization

### Privacy Management
- **Private Contacts**: Contacts can be marked private with specific user access
- **Backward Compatibility**: Supports both old and new privacy field formats
- **User Validation**: Ensures allowed users exist in the system
- **Access Filtering**: Automatic privacy filtering in list operations

### Data Management
- **Comprehensive CRUD**: Full contact lifecycle management
- **Project Integration**: Links contacts with associated projects
- **Client Filtering**: Filter contacts by client organization
- **Audit Trail**: Complete creation and modification tracking

## API Endpoints

### Core CRUD Operations
- `POST /contacts` - Create new contact with privacy settings
- `GET /contacts` - List contacts with filtering and pagination
- `GET /contacts?contactID=xyz` - Get specific contact with projects
- `PUT /contacts` - Update contact with privacy changes
- `DELETE /contacts` - Delete single or multiple contacts

### Special Endpoints
- `GET /contacts?debug=true` - Debug permissions information
- `GET /contacts?endpoint=users` - Get users for privacy dropdown
- `GET /permissions-test` - Comprehensive permissions testing

## Database Schema

### Contacts Table
```json
{
  "contactID": "uuid",
  "displayID": "CONT-00001",
  "firstName": "string",
  "lastName": "string",
  "officialEmail": "string",
  "clientID": "uuid",
  "private": "boolean",
  "allowedUsers": ["userID1", "userID2"],
  "createdBy": "userID",
  "createdAt": "ISO-8601",
  "updatedBy": "userID",
  "updatedAt": "ISO-8601"
}
```

### Privacy Schema
- `private`: Boolean indicating if contact is private
- `allowedUsers`: Array of user IDs who can access private contact
- `privacy`: Legacy field for backward compatibility

## Error Handling

### Authorization Errors (403)
- Detailed error messages with pattern information
- Creator-based access hints
- Scope summaries for debugging

### Validation Errors (400)
- Missing required fields
- Duplicate email detection
- Invalid user IDs in privacy settings

### System Errors (500)
- Comprehensive error logging
- Error IDs for tracking
- Stack trace logging for debugging

## Logging Strategy

### Log Levels
- **INFO**: Operation summaries, successful operations
- **WARNING**: Permission denials, data inconsistencies
- **ERROR**: System failures, database errors
- **DEBUG**: Detailed debugging information (disabled in production)

### Key Log Events
- Contact creation/update/deletion
- Authorization decisions
- Privacy filtering operations
- Database query performance
- Error conditions with context

## Performance Considerations

### Database Optimization
- Batch operations for multiple contacts
- GSI usage for creator-based queries
- Pagination support for large datasets
- Efficient filtering strategies

### Caching Strategy
- Policy engine result caching
- User validation caching
- Client information caching

### Monitoring Points
- Response times per operation
- Authorization check performance
- Database query efficiency
- Privacy filtering impact

## Security Considerations

### Data Protection
- Private contact access control
- Email uniqueness per client
- Creator ownership tracking
- Audit trail maintenance

### Authorization Model
- Deny-wins precedence
- Override-based permissions
- Pattern-based access control
- Record-level granularity

## Migration and Compatibility

### Backward Compatibility
- Legacy privacy field support
- Existing contact format preservation
- API response format consistency
- No breaking changes to existing integrations

### Migration Path
1. Deploy new modular code (no data changes)
2. Monitor functionality and performance
3. Gradually deprecate legacy privacy fields
4. Clean up unused fields in maintenance windows

## Development Guidelines

### Adding New Features
1. Determine appropriate layer (handler/service/model)
2. Add comprehensive error handling
3. Include appropriate logging
4. Update documentation
5. Add unit tests for new functionality

### Code Style
- Follow existing naming conventions
- Include docstrings for all public methods
- Use type hints for function parameters
- Handle exceptions at appropriate levels
- Log important operations and errors

### Testing Strategy
- Unit tests for individual methods
- Integration tests for workflows
- Authorization testing with policy engine
- Privacy filtering validation
- Error condition coverage

## Troubleshooting

### Common Issues
1. **Authorization Failures**: Check policy engine configuration and user roles
2. **Privacy Access Denied**: Verify user in allowedUsers array
3. **Duplicate Email**: Ensure email uniqueness per client
4. **Performance Issues**: Check database query patterns and indexing

### Debug Endpoints
- Use `?debug=true` for permissions information
- Check authorization service logs for policy decisions
- Monitor database query performance
- Review privacy filtering results

This modular architecture provides a solid foundation for maintaining and extending the contacts API while ensuring security, performance, and reliability in production environments.