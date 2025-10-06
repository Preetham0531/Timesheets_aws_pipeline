# Business logic for approval operations
import uuid
import json
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Dict, Any, Optional
from collections import defaultdict

from models.approval_model import ApprovalModel
from models.time_entry_model import TimeEntryModel
from services.policy_service import PolicyService
from services.email_service import EmailService
from utils import (
    get_user_full_name, 
    get_project_name, 
    get_time_entry_info,
    fmt,
    resolve_task_name
)

logger = logging.getLogger("approval_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class ApprovalService:
    """Service class containing business logic for approval operations"""

    def __init__(self):
        self.approval_model = ApprovalModel()
        self.time_entry_model = TimeEntryModel()
        self.policy_service = PolicyService()
        self.email_service = EmailService()

    def raise_approvals(self, user_id: str, entry_ids: List[str]) -> Dict[str, Any]:
        """
        Business logic for raising approval requests.
        Anyone can raise approvals for entries they own or for projects they created.

        NOTE:
        - No 'TimeEntries.view' (or any 'view') checks are performed here.
        - No 'Approvals.request' (or any top-level capability) check here.
        - Domain rules (owner OR project creator) still apply per entry.
        """
        # ---- Normalize input: strip empties & dedupe while preserving order ----
        seen = set()
        norm_ids: List[str] = []
        for raw in entry_ids or []:
            if raw is None:
                continue
            s = str(raw).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            norm_ids.append(s)

        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        email_entries: List[Dict[str, Any]] = []
        email_recipients: set[str] = set()
        project_name = None

        for entry_id in norm_ids:
            # ---- Load minimal entry info (no policy checks here) ----
            info = get_time_entry_info(entry_id)
            if not info or not info.get("owner_id") or not info.get("project_id"):
                errors.append({"timeEntryID": entry_id, "error": "Time entry not found"})
                continue

            entry_owner_id = info["owner_id"]
            project_id = info["project_id"]

            # ---- Domain rule: only owner OR project creator may raise ----
            try:
                proj_creator_id = self._get_project_creator_id(project_id)
            except Exception as e:
                logger.error("Failed to get project creator for %s: %s", project_id, e)
                errors.append({"timeEntryID": entry_id, "error": "Internal error while validating project"})
                continue

            is_owner = (entry_owner_id == user_id)
            is_project_creator = (proj_creator_id == user_id)

            if not (is_owner or is_project_creator):
                errors.append({
                    "timeEntryID": entry_id,
                    "error": "Only the owner or the project creator can raise approval for this entry"
                })
                continue

            # ---- Prevent duplicate Pending approvals ----
            try:
                existing = self.approval_model.get_approvals_by_time_entry(entry_id)
                if any(str(a.get("ApprovalStatus", "")).lower() == "pending" for a in existing):
                    errors.append({"timeEntryID": entry_id, "error": "Already pending"})
                    continue
            except Exception as e:
                logger.error("Error checking duplicates for entry %s: %s", entry_id, e)
                errors.append({"timeEntryID": entry_id, "error": "Internal error while checking duplicates"})
                continue

            # ---- Identify potential approvers for notifications (policy-based) ----
            try:
                project_users = self._get_project_assigned_users(project_id) or []
                for uid in project_users:
                    if uid == user_id:  # don't notify the requester
                        continue
                    try:
                        if self.policy_service.can_do(uid, "Approvals", "approve_reject"):
                            email_recipients.add(uid)
                    except Exception as e:
                        logger.debug("can_do(Approvals.approve_reject) failed for %s: %s", uid, e)
            except Exception as e:
                logger.debug("Could not load project users for %s: %s", project_id, e)

            # ---- Create the approval record ----
            approval_id = str(uuid.uuid4())
            now_iso = datetime.utcnow().isoformat()

            try:
                approval_data = {
                    "ApprovalID": approval_id,
                    "UserID": entry_owner_id,
                    "projectID": project_id,
                    "TimeEntryID": entry_id,
                    "RequestRaisedBy": user_id,
                    "ApprovalStatus": "Pending",
                    "projectstatus": "Active",
                    "CreatedAt": now_iso,
                    "RegularHours": Decimal(str(info.get("regular", 0))),
                    "OvertimeHours": Decimal(str(info.get("overtime", 0))),
                    # required by table schema (placeholder)
                    "ManagerID": "N/A",
                }

                self.approval_model.create_approval(approval_data)

                results.append({
                    "timeEntryID": entry_id,
                    "approvalID": approval_id,
                    "status": "Pending",
                })
                email_entries.append({
                    "date": info.get("date"),
                    "task": info.get("task"),
                    "hours": info.get("total"),
                })
                project_name = project_name or info.get("project_name")

                logger.info("✅ Created approval request %s for entry %s", approval_id, entry_id)

            except Exception as e:
                logger.error("Error creating approval request for entry %s: %s", entry_id, e)
                errors.append({"timeEntryID": entry_id, "error": f"Failed to create approval: {str(e)}"})

        # ---- Send notification emails (if permitted) ----
        emails_sent = 0
        if email_entries and email_recipients:
            try:
                if self.policy_service.can_do(user_id, "Approvals", "email"):
                    requester_name = get_user_full_name(user_id) or "Someone"
                    emails_sent = self.email_service.send_approval_raised_notifications(
                        list(email_recipients), requester_name, project_name, email_entries
                    )
                    logger.info("✅ Sent email notifications to %d users", emails_sent)
            except Exception as e:
                logger.warning("Failed to send email notifications: %s", e)

        return {
            "results": results,
            "errors": errors,
            "emailsSent": emails_sent,
        }

    # -------------------------
    # Helper: tolerant TEID read
    # -------------------------
    def _extract_time_entry_id(self, approval_record: Dict[str, Any]) -> Optional[str]:
        """Pull TimeEntryID from multiple legacy key variants."""
        if not approval_record:
            return None
        for k in ("TimeEntryID","timeEntryID","time_entry_id","TimeEntryId","timeEntryId","TIMEENTRYID","timeentryid"):
            v = approval_record.get(k)
            if v:
                return str(v)
        for parent in ("Details","Meta","Payload","data","detail","metadata"):
            nested = approval_record.get(parent) or {}
            if isinstance(nested, dict):
                for k in ("TimeEntryID","timeEntryID","time_entry_id","TimeEntryId","timeEntryId","TIMEENTRYID","timeentryid"):
                    v = nested.get(k)
                    if v:
                        return str(v)
        return None

    # -------------------------
    # Helper: normalized status
    # -------------------------
    def _normalized_status(self, record: Dict[str, Any]) -> Optional[str]:
        """
        Return 'approved' | 'rejected' | 'pending' (lowercase) if determinable.
        Looks at both ApprovalStatus and ManagerID (for recovery from past swaps).
        If ApprovedAt is present and no explicit status, infer 'approved'.
        """
        candidates = [
            str(record.get("ApprovalStatus", "")).strip().lower(),
            str(record.get("ManagerID", "")).strip().lower(),
        ]
        for c in candidates:
            if c in ("approved", "rejected", "pending"):
                return c
        if record.get("ApprovedAt"):
            return "approved"
        return None

    def update_approvals(self, user_id: str, approval_ids: List[str], status: str, comments: str) -> Dict[str, Any]:
        """
        Business logic for updating approval requests (approve/reject).
        Enforces authorization checks and self-approval prevention.
        """
        # Check authorization
        try:
            if not self.policy_service.can_do(user_id, "Approvals", "approve_reject"):
                logger.warning(f"Approve/reject denied for user {user_id}: insufficient permissions")
                scope_result = self.policy_service.get_allowed_record_ids(user_id, "Approvals", "approve_reject")
                raise PermissionError({
                    "error": "Not authorized to approve or reject approval requests",
                    "pattern": scope_result.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", []),
                    "hasAllAccess": scope_result.get("all", False)
                })
        except Exception as e:
            logger.error(f"Policy engine error during approve_reject check: {e}")
            raise Exception("Authorization system error")

        now_iso = datetime.utcnow().isoformat()
        results = {"succeeded": [], "failed": [], "self_approval_blocked": []}

        # Batch load all approval records for self-approval check
        approval_records = {}
        self_approval_ids = []
        logger.info(f"Loading {len(approval_ids)} approval records for self-approval validation")
        for approval_id in approval_ids:
            try:
                approval_record = self.approval_model.get_approval_by_id(approval_id)
                if approval_record:
                    approval_records[approval_id] = approval_record
                    if approval_record.get("RequestRaisedBy") == user_id:
                        self_approval_ids.append(approval_id)
                        logger.warning(f"❌ Self-approval detected: User {user_id} cannot approve their own request {approval_id}")
                else:
                    logger.warning(f"Approval record not found: {approval_id}")
            except Exception as e:
                logger.error(f"Error loading approval record {approval_id}: {e}")

        # Block ALL self-approvals regardless of policy permissions
        if self_approval_ids:
            logger.warning(f"Blocking {len(self_approval_ids)} self-approval attempts by user {user_id}")
            for self_approval_id in self_approval_ids:
                approval_record = approval_records.get(self_approval_id, {})
                results["self_approval_blocked"].append({
                    "approvalID": self_approval_id,
                    "error": "Cannot approve your own request",
                    "requestRaisedBy": approval_record.get("RequestRaisedBy"),
                    "currentUser": user_id,
                    "businessRule": "Self-approval prevention"
                })
                results["failed"].append({
                    "approvalID": self_approval_id, 
                    "error": "Self-approval not permitted"
                })

        # Process approvals (excluding self-approvals)
        processable_ids = [aid for aid in approval_ids if aid not in self_approval_ids]
        logger.info(f"Processing {len(processable_ids)} approvals (excluded {len(self_approval_ids)} self-approvals)")
        
        emails_sent = 0
        for approval_id in processable_ids:
            try:
                # Record-level access
                if self.policy_service.is_available() and not self.policy_service.can_access_record(user_id, "Approvals", "approve_reject", approval_id):
                    logger.warning(f"Record-level access denied for approval {approval_id}")
                    results["failed"].append({
                        "approvalID": approval_id, 
                        "error": "Not authorized to approve/reject this specific request"
                    })
                    continue

                approval_record = approval_records.get(approval_id)
                if not approval_record:
                    results["failed"].append({"approvalID": approval_id, "error": "Approval request not found"})
                    continue

                # Already finalized?
                norm = self._normalized_status(approval_record)
                if norm in ("approved", "rejected"):
                    results["failed"].append({
                        "approvalID": approval_id,
                        "error": f"Approval already {norm}",
                        "currentStatus": approval_record.get("ApprovalStatus"),
                        "currentManagerID": approval_record.get("ManagerID"),
                        "approvedAt": approval_record.get("ApprovedAt"),
                        "approvedBy": approval_record.get("ApprovedBy"),
                    })
                    continue

                time_entry_id = self._extract_time_entry_id(approval_record)
                if not time_entry_id:
                    logger.debug("Approval payload keys for %s: %s", approval_id, list(approval_record.keys()))
                    logger.warning("No TimeEntryID found for approval %s — will update approval only and skip time entry update.", approval_id)

                request_raised_by = approval_record.get("RequestRaisedBy")
                logger.info(f"Processing approval {approval_id}: {status} by {user_id} for request by {request_raised_by}")

                # ✅ CORRECT ARG ORDER for the model: (approval_id, manager_id, status, comments, approved_at, approved_by)
                self.approval_model.update_approval_status(
                    approval_id,
                    "N/A",         # ManagerID (placeholder)
                    status,        # ApprovalStatus
                    comments,
                    now_iso,
                    user_id
                )

                # Update time entry only if present
                time_entry_update_skipped = False
                if time_entry_id:
                    try:
                        self.time_entry_model.update_approval_status(
                            time_entry_id, 
                            status == "Approved", 
                            status, 
                            now_iso, 
                            user_id
                        )
                    except Exception as te_err:
                        time_entry_update_skipped = True
                        logger.warning("TimeEntry update failed for %s (approval %s): %s", time_entry_id, approval_id, te_err)
                else:
                    time_entry_update_skipped = True

                # Notification
                email_sent = False
                if self.policy_service.can_do(user_id, "Approvals", "email"):
                    try:
                        email_sent = self.email_service.send_approval_decision_notification(
                            approval_id, approval_record, status, comments, user_id
                        )
                        if email_sent:
                            emails_sent += 1
                    except Exception as email_error:
                        logger.warning(f"Failed to send notification email for approval {approval_id}: {email_error}")

                results["succeeded"].append({
                    "approvalID": approval_id,
                    "status": status,
                    "timeEntryID": time_entry_id or None,
                    "requestRaisedBy": request_raised_by,
                    "approvedBy": user_id,
                    "emailSent": email_sent,
                    "timeEntryUpdateSkipped": time_entry_update_skipped,
                    "processedAt": now_iso
                })
                
                logger.info(f"✅ Successfully {status.lower()} approval {approval_id} (request by {request_raised_by}); time entry update skipped={time_entry_update_skipped}")

            except Exception as e:
                error_msg = f"Failed to process approval: {str(e)}"
                logger.error(f"Failed to process approval {approval_id}: {e}")
                results["failed"].append({
                    "approvalID": approval_id, 
                    "error": error_msg,
                    "exception": str(type(e).__name__)
                })

        results["emailsSent"] = emails_sent
        return results

    def get_approval_summary(self, user_id: str, start_date, end_date) -> Dict[str, Any]:
        """
        Business logic for getting approval summary with policy-based filtering.
        """
        # Check authorization
        try:
            if not self.policy_service.can_do(user_id, "Approvals", "view"):
                logger.warning(f"View approvals denied for user {user_id}: insufficient permissions")
                scope_result = self.policy_service.get_allowed_record_ids(user_id, "Approvals", "view")
                raise PermissionError({
                    "error": "Not authorized to view approval requests",
                    "pattern": scope_result.get("pattern", "unknown"),
                    "scopes": scope_result.get("scopes", []),
                    "hasAllAccess": scope_result.get("all", False)
                })
        except Exception as e:
            logger.error(f"Policy engine error during view check: {e}")
            raise Exception("Authorization system error")

        # Get access scope from policy engine
        try:
            access_filter = self.policy_service.get_accessible_records_filter(user_id, "Approvals", "view")
            filter_type = access_filter.get("type", "none")

            logger.info(f"📋 Policy engine response for user {user_id}: filter_type={filter_type}")
            
            allowed_project_ids = None
            allowed_user_ids = None

            if filter_type == "all":
                logger.info("User has all access to approvals")
            elif filter_type == "all_except_denied":
                denied_ids = access_filter.get("denied_ids", [])
                logger.info(f"User has all access except {len(denied_ids)} denied approvals")
            elif filter_type == "specific":
                allowed_ids = access_filter.get("allowed_ids", [])
                logger.info(f"✅ User has specific access to {len(allowed_ids)} approvals")
                # Policy engine already filtered the approval IDs correctly
                allowed_project_ids = None
                allowed_user_ids = None
            else:
                logger.warning(f"❌ POLICY: User has no access - filter_type='{filter_type}'")
                allowed_project_ids = set()
                allowed_user_ids = set()

        except Exception as e:
            logger.error(f"Error getting access filter: {e}")
            raise Exception("Access filter error")

        # Collect approval counts and data
        counts = {"Pending": 0, "Approved": 0, "Rejected": 0}
        approved_today = 0
        today = datetime.utcnow().date()

        approvals_by_status = {"Pending": [], "Approved": [], "Rejected": []}
        statusApproved_ids = []
        statusRejected_ids = []
        statusPending_ids = []

        def collect_approvals_by_status(status):
            nonlocal approved_today
            try:
                if filter_type in ("all", "all_except_denied", "specific"):
                    all_items = self.approval_model.get_approvals_by_status(status)

                    if filter_type == "specific":
                        allowed_ids_set = set(access_filter.get("allowed_ids", []))
                        items = [it for it in all_items if it.get("ApprovalID") in allowed_ids_set]
                    elif filter_type == "all_except_denied":
                        denied_ids_set = set(access_filter.get("denied_ids", []))
                        items = [it for it in all_items if it.get("ApprovalID") not in denied_ids_set]
                    else:
                        items = all_items
                else:
                    items = []

                counts[status] = len(items)
                approvals_by_status[status] = items

                for it in items:
                    aid = it["ApprovalID"]
                    st = str(it.get("ApprovalStatus", "")).lower()
                    if st == "approved":
                        statusApproved_ids.append(aid)
                        approved_at = it.get("ApprovedAt")
                        try:
                            if approved_at and datetime.fromisoformat(approved_at).date() == today:
                                approved_today += 1
                        except ValueError:
                            pass
                    elif st == "rejected":
                        statusRejected_ids.append(aid)
                    elif st == "pending":
                        statusPending_ids.append(aid)

            except Exception as e:
                logger.error(f"Error collecting approvals for status {status}: {e}")
                counts[status] = 0
                approvals_by_status[status] = []

        for st in ("Pending", "Approved", "Rejected"):
            collect_approvals_by_status(st)

        # Build weekly/daily aggregations
        weekly, daily, status_pending_details = self._build_aggregations(
            approvals_by_status, start_date, end_date, 
            allowed_project_ids, allowed_user_ids, statusPending_ids
        )

        summary = {
            "pending": counts["Pending"],
            "approved": counts["Approved"],
            "rejected": counts["Rejected"],
            "approvedToday": approved_today,
            "totalProcessed": counts["Approved"] + counts["Rejected"],
            "statusApproved": statusApproved_ids,
            "statusRejected": statusRejected_ids,
            "statusPending": statusPending_ids,
            "statusPendingDetails": status_pending_details
        }

        logger.info(f"✅ Approval summary completed: {len(weekly)} users, {sum(counts.values())} total approvals")

        return {
            "summary": summary,
            "weekly": weekly,
            "daily": daily,
            "accessInfo": {
                "filterType": filter_type,
                "scopes": access_filter.get("scopes", []),
                "pattern": access_filter.get("pattern", "unknown")
            }
        }

    def _get_project_creator_id(self, project_id: str) -> str:
        """Helper to get project creator ID"""
        try:
            from models.project_model import ProjectModel
            project_model = ProjectModel()
            return project_model.get_creator_id(project_id)
        except Exception as e:
            logger.debug(f"Could not resolve project creator for {project_id}: {e}")
            return None

    def _get_project_assigned_users(self, project_id: str) -> List[str]:
        """Helper to get users assigned to a project"""
        try:
            from models.assignment_model import AssignmentModel
            assignment_model = AssignmentModel()
            return assignment_model.get_users_for_project(project_id)
        except Exception as e:
            logger.error(f"Error getting project assigned users for {project_id}: {e}")
            return []

    def _build_aggregations(self, approvals_by_status, start_date, end_date, 
                           allowed_project_ids, allowed_user_ids, statusPending_ids):
        """Helper to build weekly/daily aggregations"""
        entry_map_pending = {}
        entry_map_approved = {}
        entry_map_rejected = {}

        def _maybe_add(approval_item, bucket: str):
            teid = approval_item.get("TimeEntryID")
            if not teid:
                return
            entry = self._first_entry_for_time_entry_id(teid)
            if not entry:
                return

            ds = entry.get("Date") or entry.get("date")
            if not ds:
                return
            try:
                d = datetime.fromisoformat(str(ds)).date()
            except ValueError:
                try:
                    d = datetime.fromisoformat(str(ds).split("T")[0]).date()
                except Exception:
                    return
            if d < start_date or d > end_date:
                return

            if allowed_project_ids is not None and entry.get("projectID") not in allowed_project_ids:
                return
            if allowed_user_ids is not None and entry.get("UserID") not in allowed_user_ids:
                return

            regs = float(entry.get("RegularHours", 0) or 0)
            ots = float(entry.get("OvertimeHours", 0) or 0)
            pname = entry.get("projectName") or get_project_name(entry.get("projectID"))
            tname = resolve_task_name(entry)

            info = {
                "user": entry.get("UserID"),
                "date": d.isoformat(),
                "regular": regs,
                "overtime": ots,
                "taskName": tname,
                "projectName": pname,
                "timeEntryID": teid,
            }

            aid = approval_item["ApprovalID"]
            if bucket == "pending":
                entry_map_pending[aid] = info
            elif bucket == "approved":
                entry_map_approved[aid] = info
            else:
                entry_map_rejected[aid] = info

        for it in approvals_by_status["Pending"]:
            _maybe_add(it, "pending")
        for it in approvals_by_status["Approved"]:
            _maybe_add(it, "approved")
        for it in approvals_by_status["Rejected"]:
            _maybe_add(it, "rejected")

        weekly_agg = defaultdict(lambda: {
            "userID": "", "userName": "",
            "pendingRegular": 0.0, "pendingOvertime": 0.0,
            "approvedRegular": 0.0, "approvedOvertime": 0.0,
            "rejectedRegular": 0.0, "rejectedOvertime": 0.0,
            "pendingIDs": [], "approvedIDs": [], "rejectedIDs": []
        })

        def bucket_entries(map_obj, key_prefix):
            for aid, info in map_obj.items():
                uid = info["user"]
                rec = weekly_agg[uid]
                rec["userID"] = uid
                rec["userName"] = self._get_user_full_name_safe(uid)
                rec[f"{key_prefix}Regular"] += info["regular"]
                rec[f"{key_prefix}Overtime"] += info["overtime"]
                rec[f"{key_prefix}IDs"].append(aid)

        bucket_entries(entry_map_pending, "pending")
        bucket_entries(entry_map_approved, "approved")
        bucket_entries(entry_map_rejected, "rejected")

        weekly = []
        for rec in weekly_agg.values():
            pr, po = rec["pendingRegular"], rec["pendingOvertime"]
            ar, ao = rec["approvedRegular"], rec["approvedOvertime"]
            rr, ro = rec["rejectedRegular"], rec["rejectedOvertime"]
            weekly.append({
                "userID": rec["userID"],
                "userName": rec["userName"],
                "weeklySubmitted": fmt(pr + po + ar + ao + rr + ro),
                "weeklyRegular": fmt(pr + ar + rr),
                "weeklyOvertime": fmt(po + ao + ro),
                "pendingCount": len(rec["pendingIDs"]),
                "approvedCount": len(rec["approvedIDs"]),
                "rejectedCount": len(rec["rejectedIDs"]),
                "pendingHours": fmt(pr + po),
                "approvedHours": fmt(ar + ao),
                "rejectedHours": fmt(rr + ro),
                "pendingIDs": rec["pendingIDs"],
                "approvedIDs": rec["approvedIDs"],
                "rejectedIDs": rec["rejectedIDs"],
            })

        # Daily aggregations
        all_dates = [(start_date + timedelta(days=i)).isoformat()
                     for i in range((end_date - start_date).days + 1)]
        daily = []

        by_user_date = defaultdict(lambda: defaultdict(list))
        def _add_to_by_user_date(map_obj):
            for aid, info in map_obj.items():
                by_user_date[info["user"]][info["date"]].append((aid, info))

        _add_to_by_user_date(entry_map_pending)
        _add_to_by_user_date(entry_map_approved)
        _add_to_by_user_date(entry_map_rejected)

        for uid, _ in weekly_agg.items():
            days = []
            per_date = by_user_date.get(uid, {})
            for ds in all_dates:
                if ds not in per_date:
                    continue
                items = per_date[ds]

                task_list = []
                for aid, info in items:
                    is_p = aid in entry_map_pending
                    is_a = aid in entry_map_approved
                    is_r = aid in entry_map_rejected
                    tot = info["regular"] + info["overtime"]
                    task_list.append({
                        "taskName": info["taskName"],
                        "projectName": info["projectName"],
                        "regularHours": fmt(info["regular"]),
                        "overtimeHours": fmt(info["overtime"]),
                        "submittedHours": fmt(tot),
                        "pendingIDs": [aid] if is_p else [],
                        "approvedIDs": [aid] if is_a else [],
                        "rejectedIDs": [aid] if is_r else [],
                        "pendingHours": fmt(tot) if is_p else fmt(0),
                        "approvedHours": fmt(tot) if is_a else fmt(0),
                        "rejectedHours": fmt(tot) if is_r else fmt(0),
                    })

                if task_list:
                    days.append({"date": ds, "tasks": task_list})

            if days:
                daily.append({"userID": uid, "userName": self._get_user_full_name_safe(uid), "dailyData": days})

        status_pending_details = []
        for aid in statusPending_ids:
            info = entry_map_pending.get(aid)
            if not info:
                continue
            status_pending_details.append({
                "approvalID": aid,
                "timeEntryID": info.get("timeEntryID"),
                "userID": info["user"],
                "userName": self._get_user_full_name_safe(info["user"]),
                "date": info["date"],
                "taskName": info["taskName"],
                "projectName": info["projectName"],
                "regularHours": fmt(info["regular"]),
                "overtimeHours": fmt(info["overtime"])
            })

        return weekly, daily, status_pending_details

    def _first_entry_for_time_entry_id(self, teid: str):
        """Helper to get first entry for a time entry ID"""
        return self.time_entry_model.get_by_time_entry_id(teid)

    def _get_user_full_name_safe(self, user_id: str) -> str:
        """Helper to safely get user full name with fallbacks"""
        try:
            name = get_user_full_name(user_id)
            if name and isinstance(name, str) and name.strip():
                return name.strip()
        except Exception:
            pass
        return f"User {user_id[:8]}"

logger.info("✅ Approval service initialized")
