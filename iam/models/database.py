"""
Database connection and table configuration.
"""
import boto3
from config import TABLE_CONFIG

_ddb = boto3.resource("dynamodb")

# Table instances
ROLES_TBL = _ddb.Table(TABLE_CONFIG["roles"])
SEQUENCES_TBL = _ddb.Table(TABLE_CONFIG["sequences"])
EMPLOYEES_TBL = _ddb.Table(TABLE_CONFIG["employees"])
GRANTS_TBL = _ddb.Table(TABLE_CONFIG["assignments"])
USERS_TBL = _ddb.Table(TABLE_CONFIG["users"])
