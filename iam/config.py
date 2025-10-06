import os

# ========= CONFIGURATION =========
TABLE_CONFIG = {
    "assignments": os.environ.get("USER_GRANTS_TABLE", "dev.UserGrants.ddb-table"),
    "roles":       os.environ.get("ROLES_TABLE",       "dev.roles_t.ddb-table"),
    "definitions": os.environ.get("DEFINITIONS_TABLE", "dev.PolicyDefinitions.ddb-table"),
    "sequences":   os.environ.get("SEQUENCES_TABLE",   "dev.Sequences.ddb-table"),
    "employees":   os.environ.get("EMPLOYEES_TABLE",   "dev.Employees.ddb-table"),
    "users":       os.environ.get("USERS_TABLE",       "dev.Users.ddb-table"),
    "role_index":  os.environ.get("ROLES_ROLE_INDEX",  "role-rid-index"),   # GSI on 'role'
    "grants_role_index": os.environ.get("GRANTS_ROLE_INDEX", "role-index"), # GSI on UserGrants.role
}

# ========= CONSTANTS =========
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "100"))
DEFAULT_PAGE_SIZE = int(os.environ.get("DEFAULT_PAGE_SIZE", "50"))
 