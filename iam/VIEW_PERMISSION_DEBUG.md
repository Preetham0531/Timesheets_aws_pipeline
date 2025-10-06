# View Permission Debug Guide 🔍

## Issue Summary

**Problem**: User has `view: ["all"]` in override but cannot view a specific role by RID.

**Override Configuration**:
```json
{
  "userID": "1e3d632c-5443-4878-a58c-e81d4cae6b35",
  "ovID": "B#OVR#MODULE#IAM#CTX#IAM",
  "Allow": {
    "view": ["all"],                          ✅ Should grant access to ALL roles
    "modify": ["selected_by_creator"],
    "delete": ["selected_by_creator"]
  },
  "SelectedCreators": {
    "modify": {"e5ee885a-...": "venkat"},
    "delete": {"e5ee885a-...": "venkat"}
  }
}
```

**Expected**: User should be able to view all roles  
**Actual**: Getting 403 Forbidden when viewing specific role by RID

---

## Request Flow Analysis

### 1. API Request
```
GET /roles?rid=3f2541b9-51ba-4ea1-94ed-efe4ecd8e47c&userID=1e3d632c-5443-4878-a58c-e81d4cae6b35
```

### 2. Handler Processing
- **Method**: GET
- **Type**: global_role (specific role view)
- **Handler**: `handle_specific_role_view_by_rid()`

### 3. Permission Check (Line 100 of role_retrieval_service.py)
```python
if not can_access_record(user_id, "IAM", "view", rid):
    return build_response(..., error="Not authorized to view role", status=403)
```

### 4. Policy Engine Evaluation
```python
def can_access_record(user_id, module, action, record_id):
    scope_result = get_allowed_record_ids(user_id, module, action)
    
    # Check if denied
    if record_id in scope_result.get("denied_ids", set()):
        return False
    
    # Check if all access ⭐ KEY CHECK
    if scope_result.get("all", False):
        return True  # Should return True here!
    
    # Check if in specific allowed IDs
    return record_id in scope_result.get("ids", set())
```

---

## Root Cause Investigation

### Hypothesis 1: Override Not Being Applied ❌
**Evidence Against**: Logs show "Setting selected creators for modify" and "delete", which means the override IS being loaded and processed.

### Hypothesis 2: Base Role Conflicting ⚠️
**Possible**: The base role "Q_A" might have conflicting permissions that override the module-specific override.

**Log Evidence**:
```
Loaded 2 assignments for user 1e3d632c-5443-4878-a58c-e81d4cae6b35
Built 5 total rules for IAM
Allow rules: 5
```

The system loaded 2 assignments (likely: base role + override) and built 5 rules. We need to see what those 5 rules actually contain.

### Hypothesis 3: Policy Merge Logic Issue ⭐ LIKELY
**Theory**: The policy engine might not be correctly handling the `view: ["all"]` scope when combined with other action-specific scopes in the same override.

**Key Question**: Is `get_allowed_record_ids()` returning `all: True` for the `view` action?

---

## Debug Enhancements Added

### 1. Enhanced `get_allowed_record_ids` Logging
```python
logger.info(f"🔍 get_allowed_record_ids RESULT for {user_id}.{module}.{action}:")
logger.info(f"   - all: {result.get('all', False)}")
logger.info(f"   - ids count: {len(result.get('ids', set()) or set())}")
logger.info(f"   - denied_ids count: {len(result.get('denied_ids', set()) or set())}")
logger.info(f"   - pattern: {result.get('pattern', 'N/A')}")
logger.info(f"   - scopes: {result.get('scopes', [])}")
```

### 2. Enhanced `can_access_record` Logging
```python
logger.info(f"🔍 can_access_record CHECK for RID={record_id}")
logger.info(f"   - scope_result.all: {scope_result.get('all', False)}")
logger.info(f"   - scope_result.pattern: {scope_result.get('pattern', 'N/A')}")
```

---

## Testing Steps

### Step 1: Deploy Updated Code
Deploy the code with enhanced logging to Lambda.

### Step 2: Make Test Request
```bash
curl "https://8vts5bnw97.execute-api.ap-south-1.amazonaws.com/dev/roles?rid=3f2541b9-51ba-4ea1-94ed-efe4ecd8e47c&userID=1e3d632c-5443-4878-a58c-e81d4cae6b35"
```

### Step 3: Check CloudWatch Logs
Look for these specific log entries:

**Expected Pattern for Success**:
```
🔍 get_allowed_record_ids RESULT for 1e3d632c-...IAM.view:
   - all: True                    ⭐ Should be True
   - ids count: 0
   - denied_ids count: 0
   - pattern: all
   - scopes: ['all']

🔍 can_access_record CHECK for RID=3f2541b9-...
   - scope_result.all: True       ⭐ Should be True
   - scope_result.pattern: all
   
✅ Access GRANTED for 3f2541b9-...: all access (not denied)
```

**If Failing Pattern**:
```
🔍 get_allowed_record_ids RESULT for 1e3d632c-...IAM.view:
   - all: False                   ❌ PROBLEM: Should be True!
   - ids count: X
   - denied_ids count: 0
   - pattern: specific
   - scopes: [...]

🔍 can_access_record CHECK for RID=3f2541b9-...
   - scope_result.all: False      ❌ PROBLEM: Should be True!
   - scope_result.pattern: specific
   
❌ Access DENIED for 3f2541b9-...: not in allowed list (total allowed: X)
```

---

## Potential Solutions

### Solution 1: Check Base Role Permissions
Query the base role "Q_A" to see its IAM module permissions:

```sql
-- Check what permissions Q_A has for IAM
SELECT * FROM roles WHERE role = 'Q_A'
```

If the base role has restrictive IAM permissions, they might be interfering.

### Solution 2: Verify Override Precedence
The system should prioritize override rules over base role rules. Check `_split_override_role_rules()` function:

```python
def _split_override_role_rules(rules):
    overrides = [r for r in rules if r.get("_source") == "override"]
    roles = [r for r in rules if r.get("_source") == "role"]
    others = [r for r in rules if r.get("_source") not in ("override", "role")]
    return overrides, roles, others

# Usage:
effective = overrides if overrides else (roles + others)
```

**Expected**: If overrides exist, they should COMPLETELY replace role rules.

### Solution 3: Fix Rule Building Logic
If the issue is in how rules are built from the override, check the `_gather_rules_for_action()` function to ensure `view: ["all"]` is correctly translated to a rule with `_entry: ["all"]`.

---

## Verification Checklist

After deploying the debug version:

- [ ] CloudWatch logs show `get_allowed_record_ids` result
- [ ] Check if `all: True` for view action
- [ ] Check if `can_access_record` receives `all: True`
- [ ] Identify where the logic breaks
- [ ] Review base role permissions for conflicts
- [ ] Verify override precedence logic

---

## Expected Fix

Once we identify where the logic breaks from the enhanced logs, the fix will likely be one of:

1. **Override Precedence**: Ensure override rules completely replace base role rules
2. **Scope Translation**: Ensure `view: ["all"]` is correctly translated to `_entry: ["all"]`
3. **Rule Merging**: Fix any logic that incorrectly merges or overrides the "all" scope

---

## Quick Workaround (Temporary)

If you need immediate access, you can modify the override to use a different approach:

```json
{
  "Allow": {
    "view": ["all"],
    "modify": ["all"],
    "delete": ["all"]
  },
  "Deny": {
    "modify": ["deny"],
    "delete": ["deny"]
  },
  "DeniedIds": {
    "modify": ["*"],  // Deny all except...
    "delete": ["*"]   // Deny all except...
  },
  "SelectedCreators": {
    "modify": {"e5ee885a-...": "venkat"},  // These override the deny
    "delete": {"e5ee885a-...": "venkat"}
  }
}
```

But this is complex and not recommended - the original configuration SHOULD work!

---

## Next Steps

1. **Deploy updated code** with enhanced logging
2. **Make test request** and capture CloudWatch logs
3. **Share the specific log entries** showing:
   - `get_allowed_record_ids RESULT` for view action
   - `can_access_record CHECK` for the specific RID
4. **Identify the exact point** where `all: True` is not being set or used correctly
5. **Apply targeted fix** based on the findings

---

## Contact

Once you have the CloudWatch logs with the new debug output, share them and we can pinpoint the exact issue and provide a precise fix!

The enhanced logging will tell us EXACTLY where the problem is. 🎯
