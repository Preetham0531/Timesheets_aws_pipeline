# Request handlers for approval operations
import json
import logging
from typing import Dict, Any

from services.approval_service import ApprovalService
from services.policy_service import PolicyService
from utils import build_response, get_cors_headers, get_user_id

logger = logging.getLogger("approval_handlers")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

def handle_raise_approval(event, body, user_context):
    """
    Handler for raising approval requests.

    Responsibilities (handler only):
      • Parse & validate request input (shape only, not business rules).
      • Normalize IDs, dedupe, basic sanity limits.
      • Delegate to ApprovalService for ALL authz/business checks.
      • Map service results to HTTP status with clear payload.
      • Apply CORS headers.

    IMPORTANT:
      • No TimeEntries.view (or any 'view') policy checks here.
      • Authorization & domain validations are done inside ApprovalService.
    """
    headers = get_cors_headers(event)

    user_id = get_user_id(user_context)
    if not user_id:
        resp = build_response(event, error="Unauthorized", status=401)
        resp["headers"] = headers
        return resp

    logger.info("Raise approval request by user %s", user_id)

    # ---- Input validation (shape only) ----
    entry_ids = body.get("timeEntryIDs", [])
    if isinstance(entry_ids, str):
        entry_ids = [entry_ids]

    if not isinstance(entry_ids, list):
        resp = build_response(event, error="timeEntryIDs must be a list", status=400)
        resp["headers"] = headers
        return resp

    # Normalize, strip empties, dedupe, keep original order
    norm_ids = []
    seen = set()
    for raw in entry_ids:
        if raw is None:
            continue
        s = str(raw).strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        norm_ids.append(s)

    if not norm_ids:
        resp = build_response(event, error="timeEntryIDs must be a non-empty list", status=400)
        resp["headers"] = headers
        return resp

    # Optional: guardrail on batch size (tune as needed)
    MAX_IDS = 200
    if len(norm_ids) > MAX_IDS:
        resp = build_response(
            event,
            error=f"Too many IDs: {len(norm_ids)} > {MAX_IDS}. Submit in smaller batches.",
            status=413,  # Payload Too Large
        )
        resp["headers"] = headers
        return resp

    # ---- Delegate to service (ALL business rules & authz happen there) ----
    try:
        service = ApprovalService()
        result = service.raise_approvals(user_id, norm_ids)

        # Expected result shape:
        # {
        #   "results": [{ "timeEntryID": "...", "status": "raised" }, ...],
        #   "errors":  [{ "timeEntryID": "...", "error": "Not authorized" }, ...],
        #   "emailsSent": [...optional details...]
        # }

        total = len(norm_ids)
        ok = len(result.get("results", []))
        errs = result.get("errors", [])
        failed = len(errs)

        # Identify pure-authorization errors (string match pattern kept from your code)
        auth_errs = [
            e for e in errs
            if "owner or the project creator" in str(e.get("error", "")) or
               "Not authorized" in str(e.get("error", ""))
        ]

        # Status mapping (no view checks here; we only interpret service output)
        if ok == 0 and failed > 0:
            status_code = 403 if len(auth_errs) == failed else 400
        elif ok > 0 and failed > 0:
            status_code = 207  # Multi-Status
        else:
            status_code = 200

        payload = {
            "message": f"Processed {ok} of {total} approval requests",
            "results": result.get("results", []),
            "errors": errs,
            "emailsSent": result.get("emailsSent", []),
            "summary": {
                "total": total,
                "successful": ok,
                "failed": failed,
                "authorizationErrors": len(auth_errs),
                "deduplicated": len(norm_ids) != len(entry_ids),
            },
        }

        resp = build_response(data=payload, status=status_code, event=event)
        resp["headers"] = headers
        return resp

    except KnownValidationError as ve:
        # If your service raises typed exceptions, map them cleanly.
        logger.warning("Validation error in raise_approvals: %s", ve)
        resp = build_response(event, error=str(ve), status=400)
        resp["headers"] = headers
        return resp

    except KnownAuthorizationError as ae:
        logger.warning("Authorization error in raise_approvals: %s", ae)
        resp = build_response(event, error="Not authorized", status=403)
        resp["headers"] = headers
        return resp

    except Exception as e:
        # Generic safety net
        logger.error("Service error in raise_approval: %s", e, exc_info=True)
        resp = build_response(event, error="Internal server error", status=500)
        resp["headers"] = headers
        return resp

def handle_update_approval(event, body, user_context):
    """
    Handler for updating approval requests (approve/reject).
    Validates input, delegates business logic to service layer.
    """
    headers = get_cors_headers(event)
    user_id = user_context["user_id"]
    
    logger.info(f"Update approval request by user {user_id}")

    # Input validation
    approval_ids = body.get("approvalIDs")
    if not isinstance(approval_ids, list) or not approval_ids or not all(isinstance(aid, str) for aid in approval_ids):
        resp = build_response(
            data={"error": "approvalIDs must be a non-empty list of strings"},
            status=400,
            event=event
        )
        resp["headers"] = headers
        return resp

    status = body.get("status")
    if status not in ("Approved", "Rejected"):
        resp = build_response(
            data={"error": "status must be 'Approved' or 'Rejected'"},
            status=400,
            event=event
        )
        resp["headers"] = headers
        return resp

    comments = body.get("comments", "")

    # Delegate to service
    try:
        service = ApprovalService()
        result = service.update_approvals(user_id, approval_ids, status, comments)
        
        total = len(approval_ids)
        succeeded = len(result["succeeded"])
        failed = len(result["failed"])
        self_blocked = len(result["self_approval_blocked"])

        # Determine response status and message
        if succeeded == 0:
            if self_blocked > 0 and failed == self_blocked:
                response_data = {
                    "error": "Cannot approve your own requests",
                    "message": f"Blocked {self_blocked} self-approval attempts",
                    "results": result,
                    "statistics": {
                        "total": total,
                        "succeeded": succeeded,
                        "failed": failed,
                        "selfApprovalBlocked": self_blocked,
                        "emailsSent": result["emailsSent"]
                    }
                }
                status_code = 403
            else:
                response_data = {
                    "error": "Failed to process any approval requests",
                    "results": result,
                    "statistics": {
                        "total": total,
                        "succeeded": succeeded,
                        "failed": failed,
                        "selfApprovalBlocked": self_blocked,
                        "emailsSent": result["emailsSent"]
                    }
                }
                status_code = 400
        else:
            response_data = {
                "message": f"Successfully processed {succeeded} of {total} approval requests",
                "results": result,
                "statistics": {
                    "total": total,
                    "succeeded": succeeded,
                    "failed": failed,
                    "selfApprovalBlocked": self_blocked,
                    "emailsSent": result["emailsSent"]
                }
            }
            status_code = 200

        if self_blocked > 0:
            response_data["warnings"] = [
                f"Blocked {self_blocked} self-approval attempts - users cannot approve their own requests"
            ]

        resp = build_response(
            data=response_data,
            status=status_code,
            event=event
        )
        resp["headers"] = headers
        return resp

    except Exception as e:
        logger.error(f"Service error in update_approval: {e}")
        resp = build_response(event, error="Internal server error", status=500)
        resp["headers"] = headers
        return resp

def handle_get_approval_summary(event, user_context):
    """
    Handler for getting approval summary with date range filtering.
    Validates parameters, delegates business logic to service layer.
    """
    headers = get_cors_headers(event)
    user_id = user_context["user_id"]
    params = event.get("queryStringParameters") or {}

    logger.info(f"Approval summary request by user {user_id}")

    # Date range validation
    start_str = params.get("startDate")
    end_str = params.get("endDate")
    if not start_str or not end_str:
        resp = build_response(
            None,
            error="Validation error",
            fields={"startDate/endDate": "Both required in YYYY-MM-DD"},
            status=400,
            event=event
        )
        resp["headers"] = headers
        return resp

    try:
        from datetime import datetime
        start_date = datetime.fromisoformat(start_str).date()
        end_date = datetime.fromisoformat(end_str).date()
    except ValueError:
        resp = build_response(
            None,
            error="Validation error",
            fields={"startDate/endDate": "Invalid format; use YYYY-MM-DD"},
            status=400,
            event=event
        )
        resp["headers"] = headers
        return resp

    # Delegate to service
    try:
        service = ApprovalService()
        result = service.get_approval_summary(user_id, start_date, end_date)
        
        resp = build_response(
            None,
            data=result,
            status=200,
            event=event
        )
        resp["headers"] = headers
        return resp

    except Exception as e:
        logger.error(f"Service error in get_approval_summary: {e}")
        resp = build_response(event, error="Internal server error", status=500)
        resp["headers"] = headers
        return resp

def handle_permissions_test(event, user_context):
    """Handler for testing permissions (debugging endpoint)"""
    qs = event.get("queryStringParameters") or {}
    user_id = user_context["user_id"]
    
    test_user_id = qs.get("testUserId", user_id)
    approval_id = qs.get("approvalID")
    
    try:
        policy_service = PolicyService()
        if not policy_service.is_available():
            return build_response(
                event=event,
                data={"error": "Policy engine not available"},
                status=503
            )
        
        if approval_id:
            test_results = policy_service.get_approval_permissions_summary(test_user_id, approval_id)
        else:
            test_results = policy_service.get_approval_permissions_summary(test_user_id)
        
        return build_response(
            event=event,
            data={
                "testResults": test_results,
                "currentUser": user_id,
                "testUser": test_user_id
            },
            status=200
        )
        
    except Exception as e:
        logger.error(f"Permissions test failed: {e}")
        return build_response(event, error="Internal server error", status=500)

logger.info("✅ Approval handlers initialized")