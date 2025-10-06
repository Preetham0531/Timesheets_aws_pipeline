# Project Documentation — `PROJECT_DOCUMENTATION.md`

## 1. Title & One-line Summary
- Timesheets Project
- A modular AWS serverless backend for timesheets, approvals, IAM roles, projects/clients/contacts, and related workflows using API Gateway, Lambda, DynamoDB, and SES. [INFERRED]

## 2. Quick Stats
- Files scanned: ~200 (Python modules, Markdown docs, a few cache files; binaries and .pyc ignored) [INFERRED]
- Languages & runtimes: Python 3.x; Markdown; minimal JSON/YAML inline. [INFERRED]
- Main AWS services: API Gateway (proxy), Lambda, DynamoDB, SES, S3 (uploads), CloudWatch Logs. [INFERRED]
- Documentation completeness score: 70/100 (good READMEs and inline logging; limited docstrings and typed schemas). [INFERRED]

## 3. Table of Contents
- Architecture Overview
- Getting Started
- Configuration & Secrets
- Dependencies & Requirements
- API Reference
- File-by-File Documentation
- Data Models & Storage
- Observability, Logging & Monitoring
- Security Review
- Deployment & CI/CD
- Testing & Validation
- Maintenance & Contribution Notes
- Appendix
- Final Summary & Next Steps

## 4. Getting Started (developer)
- Prerequisites:
  - Python 3.11+
  - AWS CLI v2 configured with credentials and region
  - boto3 installed (implicitly via requirements) [INFERRED]
- Setup:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
# If requirements.txt existed, use: pip install -r requirements.txt
pip install boto3
```
- Local run (Lambda-style):
```bash
# Example: invoke approvals lambda locally via a small driver
python -c 'import json; from approvals.lambda_function import lambda_handler; 
print(lambda_handler({"httpMethod":"GET","path":"/approvals","queryStringParameters":{"action":"summary","startDate":"2025-01-01","endDate":"2025-01-31"},"requestContext":{"authorizer":{"user_id":"u1","role":"admin","email":"u1@example.com"}}}, None))'
```
- Tests and linters:
```bash
# If pytest/ruff present; not included in repo explicitly
pytest -q
ruff .
```

## 5. Architecture Overview
- Components:
  - API Gateway proxy to multiple Lambda handlers per domain (approvals, timeentries, projects_table, client_table, contacts, IAM, user_login, user_routes, tasks, lookup, dashboard, update_password, project_assignment).
  - DynamoDB tables for entities (Users, Employees, Roles, Assignments, Projects, Clients, Contacts, TimeEntries, Approvals, Tasks, etc.).
  - SES for email notifications; S3 for attachments.
- Flow (ASCII):
```
Client → API Gateway → Lambda (domain handler) → DynamoDB
                              ↘ SES (emails)   ↘ S3 (files)
```
- Data flow (timesheet approval): user raises approval → Lambda validates and writes Approval record → optional emails to approvers → approver updates status → status reflected in Approval and TimeEntry. [INFERRED]
- Deployment mechanism: Not explicitly defined (no SAM/Serverless config). Likely manual or CI/CD zipped Lambda deployments. [INFERRED]

## 6. Configuration & Secrets
- Environment variables detected (examples; not exhaustive):
  - Table names: USERS_TABLE, EMPLOYEE_TABLE, PROJECTS_TABLE, CLIENTS_TABLE, CONTACTS_TABLE, ROLE_PRIVILEGES_TABLE, SEQUENCES_TABLE, ASSIGNMENTS_TABLE, TIME_ENTRIES_TABLE, APPROVALS_TABLE, TASKS_TABLE, BACKTRACK_PERMISSIONS_TABLE, PTO_TABLE, ROLE_POLICIES_TABLE, CREDENTIALS_TABLE, ENTRIES_TABLE.
  - Messaging/Email: SES_SENDER_EMAIL, SES_SOURCE_EMAIL.
  - Auth: JWT_SECRET, FRONTEND_URL.
  - Storage: S3_BUCKET_NAME.
  - Policy engine: POLICY_ENGINE_LOG_LEVEL; ROLE_BY_NAME_INDEX.
- Storage recommendations:
  - Secrets: JWT_SECRET, SES credentials (if any), S3 credentials should be managed via AWS Secrets Manager/SSM Parameter Store.
  - Table names and GSI names via SSM parameters or env files per stage.
- Example .env (do not commit):
```env
USERS_TABLE=dev.Users.ddb-table
APPROVALS_TABLE=dev.Approvals.ddb-table
TIME_ENTRIES_TABLE=dev.TimeEntries.ddb-table
PROJECTS_TABLE=dev.Projects.ddb-table
S3_BUCKET_NAME=dev-timesheets-uploads
SES_SENDER_EMAIL=no-reply@example.com
JWT_SECRET=replace-with-strong-secret
POLICY_ENGINE_LOG_LEVEL=INFO
```

## 7. Dependencies & Requirements
- Python libraries used: boto3 (AWS), json, logging, traceback, typing, base64, datetime, decimal, collections.
- Reason: AWS access, serialization, logging.
- No native/binary extensions detected. [INFERRED]

## 8. API Reference (auto-generated)
- Approvals API (approvals/lambda_function.py):
  - Endpoint: GET /approvals?action=summary&startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
    - Purpose: Fetch approval statistics and details.
    - Auth: Custom authorizer in requestContext.authorizer.
    - Request: query params startDate, endDate; header auth via gateway; example above.
    - Response: JSON with summary, daily/weekly aggregates; errors 400/401/500.
    - Notes: Debug endpoint GET /approvals/permissions-test or ?debug=true.
  - Endpoint: POST /approvals { action: "raise", timeEntryIDs: [..] }
    - Purpose: Create approval requests.
    - Response: Results/errors, 200/207/400/403.
  - Endpoint: POST /approvals { action: "update", approvalIDs: [..], status: "Approved|Rejected", comments?: string }
    - Purpose: Approve or reject.

- Timeentries API (timeentries/lambda_function.py):
  - GET /timeentries?action=getFilterData|getTimeSummary|usersData|getProjects
  - POST /timeentries { action: createOrUpdateEntry|raiseBacktrack|approveBacktrack|submitPTO|approvePTO }
  - DELETE /timeentries (body defines deletions)
  - Auth: requestContext.authorizer.

- Projects API (projects_table/lambda_function.py):
  - Standard CRUD via GET/POST/PUT/DELETE; debug GET /permissions-test.

- IAM Roles API (iam/lambda_function.py):
  - GET/POST/PUT/DELETE; OPTIONS for metadata; custom policy engine.

- User Routes (user_routes/lambda_function.py):
  - POST actions: signin, forgot-password-request, set-password-from-token, forgot-password-reset, refresh-token.

[INFERRED] Paths are conceptual; actual API Gateway stage/paths depend on deployment configuration not included here.

## 9. File-by-File Documentation (selected core files)

### approvals/lambda_function.py
**Purpose:** Routes approvals requests; handles CORS/auth; delegates to handlers; adds metadata and error handling.
**What I read:**
- Lines 39–55: parse method, support OPTIONS.
- Lines 56–67: authorizer extraction with 401 on failure.
- Lines 79–106: route GET summary and POST raise/update; debug path.
- Lines 120–136: inject _meta into successful bodies.
**Inputs & Outputs:** API Gateway proxy event; outputs API Gateway response JSON.
**External dependencies:** get_cors_headers; handlers; policy engine indirectly.
**Runtime considerations:** Logger configured at import.
**Security considerations:** Relies on authorizer; no PII in logs.
**Logging & Error handling:** Info+error; stack trace on 500 with errorId.
**Test coverage notes:** Works with mocked event and handlers.
**Example usage:** see Getting Started local invocation.
**Cross-file references:** approvals/handlers/approval_handlers.py, approvals/utils.py.
**Documentation completeness:** 3/5.
**Suggested improvements:** Standardize error schema; add body size guard; gate debug endpoint by env.

### approvals/handlers/approval_handlers.py
**Purpose:** Validate inputs and delegate to ApprovalService; build HTTP responses.
**What I read:**
- Input normalization/deduplication; batch size check (200); partial 207 responses; undefined exceptions referenced.
**Inputs & Outputs:** API event/body, user_context; returns HTTP response.
**External dependencies:** ApprovalService, PolicyService, utils.
**Runtime considerations:** Logging configured on import.
**Security considerations:** Defers auth to service; safe.
**Logging & Error handling:** Reasonable; undefined exception classes present.
**Test coverage notes:** Service can be mocked.
**Example usage:** POST body with action raise/update.
**Cross-file references:** approvals/services/*, approvals/utils.py.
**Documentation completeness:** 3/5.
**Suggested improvements:** Define/import KnownValidationError/KnownAuthorizationError; add idempotency guidance.

### approvals/services/approval_service.py
**Purpose:** Core business logic for raising/updating approvals and summarizing.
**What I read:**
- Dedupe entry IDs; owner or project-creator rule; duplicate pending check; create Approval; email notify based on policy; self-approval block; record-level checks; summary building with weekly/daily.
**Inputs & Outputs:** user_id, IDs, status/comments; writes approval/timeentry records; returns result dicts.
**External dependencies:** ApprovalModel, TimeEntryModel, PolicyService, EmailService.
**Runtime considerations:** Service instantiation per request.
**Security considerations:** Self-approval prevention; policy checks.
**Logging & Error handling:** Detailed info/warning/error logs.
**Test coverage notes:** Easy to mock models/policy and test.
**Example usage:** via handlers.
**Cross-file references:** approvals/models/*, approvals/services/policy_service.py.
**Documentation completeness:** 4/5.
**Suggested improvements:** Conditional put for idempotency, retries/backoff, transactional write if possible.

### approvals/models/approval_model.py
**Purpose:** DynamoDB access for approvals.
**What I read:**
- put_item on create; GSI queries by ApprovalID, TimeEntryID, ApprovalStatus; update_item uses composite key (ApprovalID, ManagerID).
**Inputs & Outputs:** dict items; returns items.
**External dependencies:** boto3.resource("dynamodb"), env vars.
**Runtime considerations:** Table instance per init.
**Security considerations:** None beyond IAM.
**Logging & Error handling:** Logs errors; re-raises.
**Test coverage notes:** Use moto/local.
**Example usage:** via ApprovalService.
**Cross-file references:** approvals/services/approval_service.py.
**Documentation completeness:** 3/5.
**Suggested improvements:** Add condition expressions and pagination loops; validate schema via env.

### timeentries/lambda_function.py
**Purpose:** Routes time-entry-related actions (filter, summary, users/projects, create/update, backtrack, PTO, delete).
**What I read:**
- OPTIONS handling; authorizer extraction; action routing per method; unified build_response; prints on exception.
**Inputs & Outputs:** API Gateway event; response JSON.
**External dependencies:** backtrack_routes, time_entry_routes, pto_routes, utils.
**Runtime considerations:** Simple; large route surface.
**Security considerations:** Authorizer context required; further checks within route handlers. [INFERRED]
**Logging & Error handling:** Printing error; should use logger.
**Test coverage notes:** Mockable with sample events.
**Example usage:** POST createOrUpdateEntry.
**Cross-file references:** timeentries/* modules.
**Documentation completeness:** 3/5.
**Suggested improvements:** Replace print with logger; standardize error shape; add method/action metadata in responses.

### iam/lambda_function.py
**Purpose:** Entry for IAM role APIs: list/create/update/delete.
**What I read:**
- OPTIONS metadata, caller extraction, method routing, policy engine availability logging.
**Inputs & Outputs:** API Gateway event; response JSON.
**External dependencies:** handlers, utils, policy_integration.
**Runtime considerations:** Logger created via logging_config.
**Security considerations:** can_do checks in sub-handlers. [INFERRED]
**Logging & Error handling:** Good; exception logs.
**Test coverage notes:** Mockable handlers.
**Example usage:** GET with query filters.
**Cross-file references:** iam/handlers/role_handler.py.
**Documentation completeness:** 4/5.
**Suggested improvements:** Body schema validation for PUT/POST.

### projects_table/lambda_function.py
**Purpose:** Project CRUD with policy engine integration.
**What I read:**
- Detailed metadata, CORS, body parsing, authorizer context, routes, and health handler.
**Inputs & Outputs:** API event; response JSON with _meta sometimes.
**External dependencies:** handlers, utils.
**Runtime considerations:** Logger configured.
**Security considerations:** Authorizer required; policy checks in services.
**Logging & Error handling:** Comprehensive; correlation IDs.
**Test coverage notes:** Mockable.
**Example usage:** POST create project with body.
**Cross-file references:** projects_table/handlers/*.
**Documentation completeness:** 4/5.
**Suggested improvements:** Remove emojis from logs; ensure env validation.

### user_routes/lambda_function.py
**Purpose:** Public auth routes (signin, password flows, refresh token).
**What I read:**
- Only POST; action map; wraps handler results; global exception fallback.
**Inputs & Outputs:** POST body JSON; response JSON.
**External dependencies:** public_routes handlers; token_utils CORS.
**Runtime considerations:** Simple.
**Security considerations:** Sensitive paths; ensure rate-limit at API layer. [INFERRED]
**Logging & Error handling:** Basic; includes error details in 500 (be cautious).
**Test coverage notes:** Mockable.
**Example usage:** POST { action: "signin", ... }.
**Cross-file references:** user_routes/public_routes.py.
**Documentation completeness:** 3/5.
**Suggested improvements:** Input validation; structured errors.

[Additional files follow the same template; see QUICK_REVIEW.md and CODE_REVIEW.md for high-level notes.] [INFERRED]

## 10. Data Models & Storage
- DynamoDB tables (from code references): Users, Employees, Roles, RolePrivileges, Assignments, Projects, Clients, Contacts, TimeEntries, Approvals, Tasks, PTO, BacktrackPermissions, Sequences, Credentials, RolePolicies. [INFERRED]
- Keys/GSIs (examples): ApprovalID-index, TimeEntryID-index, ApprovalStatus-index; createdBy-index suggested; role-rid-index; ProjectAssignments-index; GSI_UserID. Verify existence in infrastructure. [INFERRED]
- S3: Uploads for attachments and descriptions; object keys not standardized here. [INFERRED]

## 11. Observability, Logging & Monitoring
- Logging: logging module across handlers/services; includes correlation IDs; some prints remain.
- Tracing: No explicit X-Ray; consider enabling.
- Metrics/alerts: Recommend errors, duration, throttles, DLQ alarms; custom metrics for approvals created/updated, policy denies.

## 12. Security Review (docs-focused)
- Concerns: Fallback policy engine that allows all; hardcoded CORS origins; missing env validation; error messages including internal details in some endpoints; potential HTML injection if email content not sanitized.
- Mitigations: Fail-fast if policy engine unavailable in prod; centralized env/CORS; standard error shapes; sanitize all HTML; least-privilege IAM per Lambda.

## 13. Deployment & CI/CD
- Suggested pipeline:
```bash
# Package lambdas per module
zip -r approvals.zip approvals/
# Upload and update-function-code via AWS CLI
aws lambda update-function-code --function-name approvals --zip-file fileb://approvals.zip
```
- Add CI (GitHub Actions) with steps: lint, tests, package, deploy; artifact storage in S3; per-stage env params. [INFERRED]

## 14. Testing & Validation
- Run unit tests with pytest; integration via localstack or AWS test env. [INFERRED]
- Gaps: error path tests, policy deny cases, DynamoDB conditional failures, SES failure paths.
- Sample cases: self-approval block; duplicate approval raise idempotency; invalid JSON; missing authorizer.

## 15. Maintenance & Contribution Notes
- Branching: conventional main/feature assumed. [INFERRED]
- Onboarding checklist:
  - Set up Python venv and AWS CLI.
  - Configure .env/SSM params for tables and secrets.
  - Run a sample local invocation.
- Configuration changes: env variables at Lambda configuration; centralize in a shared settings module. [INFERRED]

## 16. Appendix
- Glossary: Policy Engine (RBAC evaluator with deny precedence); GSI (Global Secondary Index); CORS (Cross-Origin Resource Sharing).
- Commands: see Getting Started and Deployment.
- Auto-generated/irrelevant files: __pycache__, .pytest_cache, .DS_Store.

## 17. Final Summary & Next Steps
- Overall, a solid modular serverless backend with clear separation of concerns and strong logging. Main risks are duplicated policy engines, permissive fallbacks, and scattered configuration.
- Top 5 actions:
  1. Consolidate policy_engine into a shared package; remove duplicates (large).
  2. Centralize CORS, env validation, email/S3 utilities; remove hardcoded lists (medium).
  3. Add retries/backoff and pagination; replace scans with queries; verify GSIs (medium).
  4. Standardize error schema/logging; remove print; input schemas (pydantic/dataclasses) (small/medium).
  5. Add idempotency (conditional writes) for approval creation and critical updates (small/medium).
