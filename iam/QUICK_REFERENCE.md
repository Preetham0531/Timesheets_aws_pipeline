# 🚀 Quick Reference Guide - Refactored IAM Roles

## 📁 File Structure at a Glance

```
iam_roles/
├── lambda_function.py          → Entry point (routing)
│
├── handlers/
│   └── role_handler.py         → HTTP method routing
│
├── services/
│   ├── role_creation_service.py    → POST /roles
│   ├── role_retrieval_service.py   → GET /roles
│   ├── role_update_service.py      → PUT /roles (global)
│   ├── role_deletion_service.py    → DELETE /roles
│   ├── user_customization_service.py   → PUT /roles?user_id=...
│   └── user_role_view_service.py       → GET /roles?user_id=...
│
├── models/
│   ├── database.py                 → DB connection
│   ├── role_repository.py          → Role CRUD
│   ├── assignment_repository.py    → User assignments
│   ├── employee_repository.py      → Employee names
│   └── sequence_repository.py      → ID generation
│
├── utils/
│   ├── response_utils.py       → API responses
│   ├── validation_utils.py     → Validation
│   ├── time_utils.py           → Time/date
│   ├── token_utils.py          → Pagination
│   └── json_utils.py           → JSON serialization
│
├── policy_engine.py            → Permission engine (UNCHANGED)
├── policy_integration.py       → Engine interface
├── policies.py                 → Policy utilities
├── overrides.py                → User overrides
├── formatting.py               → Response formatting
└── config.py                   → Configuration
```

---

## 🔍 Where to Find Things

### Need to modify role creation?
→ `services/role_creation_service.py`

### Need to change how roles are retrieved?
→ `services/role_retrieval_service.py`

### Need to update database queries?
→ `models/role_repository.py` or `models/assignment_repository.py`

### Need to change API response format?
→ `utils/response_utils.py`

### Need to add validation?
→ `utils/validation_utils.py`

### Need to change permission logic?
→ **Don't touch `policy_engine.py`!** Use `policy_integration.py` instead

### Need to see request flow?
→ `lambda_function.py` → `handlers/` → `services/` → `models/`

---

## 🎯 Common Tasks

### Add a New Endpoint
1. Create function in `services/`
2. Add routing in `handlers/role_handler.py`
3. Export from `services/__init__.py`

### Add Database Operation
1. Create function in `models/`
2. Export from `models/__init__.py`
3. Use in service layer

### Change Response Format
1. Modify `utils/response_utils.py`
2. Changes apply everywhere

### Debug an Issue
1. Check logs (structured logging)
2. Add debug in service layer
3. Check policy engine if permissions issue

---

## 📝 Import Patterns

```python
# In service files:
from models import load_role_by_rid, get_employee_name
from utils import build_response, now_iso
from policy_integration import can_do, get_allowed_record_ids

# In handler files:
from services import create_role, handle_roles_list_view
from utils import build_response, decode_token

# In model files:
from .database import ROLES_TBL
from boto3.dynamodb.conditions import Key
```

---

## 🛠 Key Functions

### Services Layer
```python
create_role(event, caller_id)           # Create new role
handle_roles_list_view(user_id, ...)    # List all roles
handle_specific_role_view_by_rid(...)   # Get role by ID
handle_global_role_update(...)          # Update role
delete_role(event, caller_id)           # Delete role
handle_user_role_customization(...)     # User overrides
```

### Models Layer
```python
load_role_by_rid(rid)                   # Get role by ID
load_role_by_name(role_name)            # Get role by name
scan_all_roles()                        # Get all roles
load_user_assignments(user_id)          # Get user's assignments
get_employee_name(employee_id)          # Get user name
```

### Utils Layer
```python
build_response(event, data, status)     # Build API response
now_iso()                               # Current timestamp
json_clean(obj)                         # Clean DynamoDB types
encode_token(lek) / decode_token(tok)   # Pagination
```

---

## ⚡ Quick Tips

1. **Always use `build_response()`** for API responses
2. **Use models layer** for all database operations
3. **Keep services focused** on business logic only
4. **Log errors** at service layer, not in models
5. **Validate early** in handlers or services
6. **Never modify** `policy_engine.py`

---

## 🚨 What NOT to Do

❌ Don't put database code in services  
❌ Don't put business logic in handlers  
❌ Don't modify policy_engine.py  
❌ Don't create new DB connections (use models/database.py)  
❌ Don't duplicate utilities (check utils/ first)  

---

## ✅ What TO Do

✅ Use existing utilities from utils/  
✅ Put DB operations in models/  
✅ Put business logic in services/  
✅ Keep handlers thin (just routing/validation)  
✅ Write clear error messages  
✅ Add docstrings to new functions  
✅ Update documentation when adding features  

---

## 🎓 Need Help?

1. Check `docs/OVERVIEW.md` for detailed documentation
2. Look at existing code for patterns
3. Follow the same structure as existing services
4. Keep separation of concerns

---

**Remember**: The code is now organized by **function**, not by **feature**. This makes it easy to find and modify specific types of operations.
