"""
Models package for data access layer.
"""
from .database import ROLES_TBL, SEQUENCES_TBL, EMPLOYEES_TBL, GRANTS_TBL, USERS_TBL
from .role_repository import (
    scan_all_roles,
    load_role_by_rid,
    load_role_by_name,
    batch_get_roles_by_ids,
    role_exists
)
from .assignment_repository import (
    load_user_assignments,
    list_users_by_role,
    validate_target_user
)
from .employee_repository import get_employee_name
from .sequence_repository import update_sequence_and_get_display

__all__ = [
    'ROLES_TBL',
    'SEQUENCES_TBL',
    'EMPLOYEES_TBL',
    'GRANTS_TBL',
    'USERS_TBL',
    'scan_all_roles',
    'load_role_by_rid',
    'load_role_by_name',
    'batch_get_roles_by_ids',
    'role_exists',
    'load_user_assignments',
    'list_users_by_role',
    'validate_target_user',
    'get_employee_name',
    'update_sequence_and_get_display'
]
