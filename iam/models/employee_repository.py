"""
Employee repository for database operations on employees.
"""
from logging_config import create_logger
from .database import EMPLOYEES_TBL

logger = create_logger("models.employee_repository")


def get_employee_name(employee_id: str) -> str:
    """Get full name of an employee by ID."""
    try:
        item = EMPLOYEES_TBL.get_item(Key={"employeeID": str(employee_id)}).get("Item", {}) or {}
    except Exception:
        item = {}
    
    first = (item.get("firstName") or "").strip()
    last = (item.get("lastName") or "").strip()
    return f"{first} {last}".strip() or "there"
