# Email notification service
import logging
from typing import List, Set, Dict, Any

from utils import (
    send_email, 
    get_user_email, 
    get_user_full_name,
    get_time_entry_info
)

logger = logging.getLogger("email_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class EmailService:
    """Service for sending email notifications related to approvals"""

    def send_approval_raised_notifications(self, email_recipients: Set[str], requester_name: str, 
                                          project_name: str, email_entries: List[Dict]) -> int:
        """Send notifications when approval requests are raised"""
        if not email_entries or not email_recipients:
            return 0

        emails_sent = 0
        html_rows = "".join(
            f"<tr>"
            f"<td style='padding:4px;border:1px solid #ccc'>{e.get('date','')}</td>"
            f"<td style='padding:4px;border:1px solid #ccc'>{e.get('task','')}</td>"
            f"<td style='padding:4px;border:1px solid #ccc'>{e.get('hours','')}</td>"
            f"</tr>"
            for e in email_entries
        )
        
        html_content = f"""
        <div>
          <p><strong>{requester_name} raised approval for {project_name or ''}:</strong></p>
          <table style="border-collapse:collapse;">
            <thead>
              <tr><th>Date</th><th>Task</th><th>Hours</th></tr>
            </thead>
            <tbody>{html_rows}</tbody>
          </table>
        </div>"""

        for uid in email_recipients:
            try:
                send_email(
                    to_email=get_user_email(uid),
                    subject=f"Approval Request for {project_name or 'a project'}",
                    plain_text=f"{requester_name} raised a request for {project_name or 'a project'}.",
                    html_content=html_content
                )
                emails_sent += 1
            except Exception as e:
                logger.debug(f"send_email failed for {uid}: {e}")

        return emails_sent

    def send_approval_decision_notification(self, approval_id: str, approval_record: Dict[str, Any], 
                                          status: str, comments: str, approver_id: str) -> bool:
        """Send notification when an approval decision is made"""
        try:
            time_entry_id = approval_record.get("TimeEntryID")
            if not time_entry_id:
                logger.warning(f"No TimeEntryID found for approval {approval_id}")
                return False

            entry_info = get_time_entry_info(time_entry_id)
            recipient_id = approval_record["UserID"]
            recipient_name = get_user_full_name(recipient_id)
            recipient_email = get_user_email(recipient_id)
            project_name = entry_info.get("project_name", "Unknown Project")
            entry_date = entry_info.get("date", "Unknown Date")
            
            # Enhanced email with approval details
            subject = f"Time Entry {status}: {project_name} ({entry_date})"
            plain_text = f"""Hi {recipient_name},

Your time entry for '{project_name}' on {entry_date} has been {status.lower()}.

Approval Details:
- Approval ID: {approval_id}
- Time Entry ID: {time_entry_id}
- {status} by: {approver_id}
- Comments: {comments or 'No comments provided'}

Please log in to your dashboard for more details.

Best regards,
Time Management System"""

            html_body = f"""
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h2 style="color: {'#28a745' if status == 'Approved' else '#dc3545'};">Time Entry {status}</h2>
    
    <p>Hi <strong>{recipient_name}</strong>,</p>
    
    <p>Your time entry for <strong>{project_name}</strong> on <strong>{entry_date}</strong> has been <strong>{status.lower()}</strong>.</p>
    
    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h4>Approval Details:</h4>
        <ul>
            <li><strong>Approval ID:</strong> {approval_id}</li>
            <li><strong>Time Entry ID:</strong> {time_entry_id}</li>
            <li><strong>{status} by:</strong> {approver_id}</li>
            <li><strong>Comments:</strong> {comments or 'No comments provided'}</li>
        </ul>
    </div>
    
    <p>Please log in to your dashboard for more details.</p>
    
    <p>Best regards,<br>Time Management System</p>
</div>"""

            send_email(
                to_email=recipient_email,
                subject=subject,
                plain_text=plain_text,
                html_content=html_body
            )
            
            logger.info(f"✅ Sent notification email for approval {approval_id} to {recipient_email}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to send notification email for approval {approval_id}: {e}")
            return False

logger.info("✅ Email service initialized")