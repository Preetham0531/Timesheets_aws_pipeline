# Creator Filter Feature Guide 🎯

## Overview

The **Creator Filter** feature allows users to view and manage IAM roles based on who created them. This is implemented through the `selected_by_creator` scope in the policy engine, enabling fine-grained access control based on role authorship.

---

## ✅ Feature Status

**Status**: ✅ **FULLY IMPLEMENTED AND FUNCTIONAL**

The creator filter functionality is already implemented in the policy engine and will work automatically when:
1. User assignments include `selected_by_creator` scope
2. `SelectedCreators` field specifies the creator IDs
3. The DynamoDB table has the `createdById-index` GSI (which you already have!)

---

## 🎨 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Request                              │
│                    GET /roles?user_id=...                        │
└──────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Policy Engine                               │
│                  (policy_engine.py)                              │
│                                                                  │
│  1. Load User Assignment from UserGrants table                   │
│  2. Check if "selected_by_creator" scope is present             │
│  3. Extract SelectedCreators for the action                      │
│  4. Query roles using createdById-index GSI                      │
│  5. Return filtered role IDs                                     │
└──────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DynamoDB Query                             │
│              Table: dev.roles_t.ddb-table                        │
│              Index: createdById-index                            │
│                                                                  │
│  Query: WHERE createdById = "e5ee885a-..."                      │
│  Returns: All roles created by that user                         │
└──────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Filtered Response                             │
│         Only shows roles from selected creators                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Database Schema

### Roles Table (dev.roles_t.ddb-table)

**Primary Key**: `rid` (String)

**Global Secondary Index**: `createdById-index`
- **Partition Key**: `createdById` (String)
- **Projection**: Include (`displayName`, `Status`, `role`, `rid`, `status`)
- **Status**: ✅ Active
- **Capacity**: On-demand

**Key Attributes**:
```json
{
  "rid": "550e8400-e29b-41d4-a716-446655440000",
  "role": "ManagerRole",
  "createdById": "e5ee885a-c7fd-4650-80ec-7299ce12257a",  ⭐ Used for filtering
  "createdBy": "venkat",
  "displayName": "Manager Role",
  "Status": "active",
  "Policies": { ... }
}
```

### User Grants Table (dev.UserGrants.ddb-table)

**Assignment Structure with Creator Filter**:
```json
{
  "userID": "ba85cf3d-a090-43da-bf8b-5a6f4eaab6ca",
  "ovID": "A#ROLE#Oracle_Apex_dev",
  "baseRole": "Oracle_Apex_dev",
  "module": "IAM",
  "Status": "active",
  "Policies": {
    "IAM": {
      "allow": {
        "view": ["selected_by_creator"],       ⭐ Key scope
        "modify": ["selected_by_creator"],
        "delete": ["selected_by_creator"]
      },
      "SelectedCreators": {                     ⭐ Creator mapping
        "view": {
          "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
        },
        "modify": {
          "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
        },
        "delete": {
          "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
        }
      }
    }
  }
}
```

---

## 🔄 How It Works

### Step-by-Step Flow

1. **User Makes Request**
   ```
   GET /roles
   Authorization: Bearer <user-token>
   ```

2. **Policy Engine Loads Assignment**
   - Queries UserGrants table for user's assignments
   - Finds assignment with `selected_by_creator` scope

3. **Extract Creator IDs**
   ```python
   SelectedCreators = {
     "view": {
       "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
     }
   }
   # Extracts: ["e5ee885a-c7fd-4650-80ec-7299ce12257a"]
   ```

4. **Query Using GSI** (Optimized)
   ```python
   table.query(
       IndexName='createdById-index',
       KeyConditionExpression=Key('createdById').eq('e5ee885a-...')
   )
   ```

5. **Return Filtered Results**
   - Only roles created by "venkat" are returned
   - User sees only the roles they're allowed to view

---

## 🎯 Use Cases

### Scenario 1: Department Manager

**Requirement**: Manager should only see roles created by department head

**Implementation**:
```json
{
  "userID": "manager-123",
  "Policies": {
    "IAM": {
      "allow": {
        "view": ["selected_by_creator"]
      },
      "SelectedCreators": {
        "view": {
          "dept-head-id": "Department Head Name"
        }
      }
    }
  }
}
```

**Result**:
- ✅ Sees: All roles created by department head
- ❌ Doesn't see: Roles created by others

---

### Scenario 2: Multi-Team Auditor

**Requirement**: Auditor needs to see roles from 3 different team leads

**Implementation**:
```json
{
  "userID": "auditor-456",
  "Policies": {
    "IAM": {
      "allow": {
        "view": ["selected_by_creator"]
      },
      "SelectedCreators": {
        "view": {
          "team-lead-1-id": "Team Lead 1",
          "team-lead-2-id": "Team Lead 2",
          "team-lead-3-id": "Team Lead 3"
        }
      }
    }
  }
}
```

**Result**:
- ✅ Sees: Union of all roles from the 3 team leads
- ❌ Doesn't see: Roles from other creators

---

### Scenario 3: Mixed Permissions

**Requirement**: User can view roles from multiple creators but only modify their own

**Implementation**:
```json
{
  "userID": "user-789",
  "Policies": {
    "IAM": {
      "allow": {
        "view": ["selected_by_creator"],
        "modify": ["selected_by_creator"]
      },
      "SelectedCreators": {
        "view": {
          "creator-1": "Creator One",
          "creator-2": "Creator Two",
          "creator-3": "Creator Three"
        },
        "modify": {
          "user-789": "Self"
        }
      }
    }
  }
}
```

**Result**:
- ✅ Can view: Roles from Creator 1, 2, and 3
- ✅ Can modify: Only roles created by themselves
- ❌ Cannot modify: Roles from other creators

---

## 🚀 How to Use

### For API Consumers

When making a GET request to retrieve roles, the policy engine automatically filters based on `SelectedCreators`:

```bash
curl -X GET https://your-api.com/roles \
  -H "Authorization: Bearer <token>"
```

**Response** (automatically filtered):
```json
{
  "ok": true,
  "roles": [
    {
      "rid": "role-1",
      "role": "ManagerRole",
      "createdById": "e5ee885a-c7fd-4650-80ec-7299ce12257a",
      "displayName": "Manager Role"
    },
    {
      "rid": "role-2",
      "role": "ViewerRole",
      "createdById": "e5ee885a-c7fd-4650-80ec-7299ce12257a",
      "displayName": "Viewer Role"
    }
  ],
  "pattern": "specific",
  "stats": {
    "totalAllowed": 2
  }
}
```

---

### For Administrators

To set up creator-based filtering for a user:

1. **Create User Assignment** with POST request to customize role:

```json
{
  "targetUserId": "ba85cf3d-a090-43da-bf8b-5a6f4eaab6ca",
  "baseRole": "Oracle_Apex_dev",
  "moduleUpdates": {
    "IAM": {
      "allow": {
        "view": ["selected_by_creator"],
        "modify": ["selected_by_creator"]
      },
      "SelectedCreators": {
        "view": {
          "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
        },
        "modify": {
          "e5ee885a-c7fd-4650-80ec-7299ce12257a": "venkat"
        }
      }
    }
  }
}
```

2. **The system will**:
   - Store the customization in UserGrants table
   - Generate correct `ovID` based on record specificity
   - Apply filters automatically on all API requests

---

## ⚡ Performance

### GSI Query (Recommended)

The implementation uses the `createdById-index` GSI for optimal performance:

**Advantages**:
- ✅ Fast lookups (milliseconds)
- ✅ Scales with number of creators, not total roles
- ✅ Supports pagination
- ✅ Low read capacity consumption

**Query Example**:
```python
response = table.query(
    IndexName='createdById-index',
    KeyConditionExpression=Key('createdById').eq(creator_id)
)
```

### Fallback to Scan

If GSI query fails, the system falls back to a table scan:

**Characteristics**:
- ⚠️ Slower for large tables
- ⚠️ Higher read capacity usage
- ✅ Still functional
- ✅ Same accuracy

---

## 🔍 Debugging

### Enable Debug Logging

The policy engine includes extensive debug logging:

```python
logger.info(f"🔍 DEBUG: Querying records for creator_id: {creator_id}")
logger.info(f"🔍 DEBUG: Using GSI '{gsi_name}' for creator {creator_id}")
logger.info(f"✅ Found record {record_id} created by {creator_id}")
```

### Check CloudWatch Logs

Look for these log patterns:

1. **Creator IDs Extraction**:
   ```
   DEBUG: Creator IDs to query: ['e5ee885a-c7fd-4650-80ec-7299ce12257a']
   ```

2. **GSI Usage**:
   ```
   DEBUG: Attempting to use GSI 'createdById-index' for creator e5ee885a-...
   ```

3. **Records Found**:
   ```
   Found record role-1 created by e5ee885a-...
   Total records found: 2 from 1 creators in IAM
   ```

---

## 🛠️ Configuration

### Module Table Config

The IAM module is configured in `policy_engine.py`:

```python
MODULE_TABLE_CONFIG = {
    "IAM": {
        "table": "dev.roles_t.ddb-table",
        "owner_field": "createdById",              ⭐ Correct field
        "primary_keys": ["rid", "role", ...]
    }
}
```

### GSI Detection

The code automatically detects the correct GSI based on `owner_field`:

```python
# For IAM: uses 'createdById-index'
# For other modules: uses 'createdBy-index'
gsi_name = 'createdById-index' if owner_field == 'createdById' else 'createdBy-index'
```

---

## ✅ Validation Checklist

Before using creator filters, ensure:

- [x] `createdById-index` GSI exists on roles table
- [x] GSI is in Active status
- [x] `createdById` field is populated for all roles
- [x] User assignments include `selected_by_creator` scope
- [x] `SelectedCreators` field maps creator IDs to names
- [x] Policy engine configuration has correct `owner_field`

---

## 🎯 Testing

### Test 1: View Roles by Creator

**Setup**:
```json
{
  "Policies": {
    "IAM": {
      "allow": {"view": ["selected_by_creator"]},
      "SelectedCreators": {
        "view": {"creator-id": "Creator Name"}
      }
    }
  }
}
```

**Expected Result**: Only roles created by `creator-id` are visible

---

### Test 2: Multiple Creators

**Setup**:
```json
{
  "SelectedCreators": {
    "view": {
      "creator-1": "Name 1",
      "creator-2": "Name 2"
    }
  }
}
```

**Expected Result**: Union of roles from both creators

---

### Test 3: Different Permissions per Action

**Setup**:
```json
{
  "allow": {
    "view": ["selected_by_creator"],
    "modify": ["selected_by_creator"]
  },
  "SelectedCreators": {
    "view": {"creator-1": "Name 1", "creator-2": "Name 2"},
    "modify": {"creator-1": "Name 1"}
  }
}
```

**Expected Result**:
- Can view roles from both creators
- Can only modify roles from creator-1

---

## 📝 Summary

The creator filter feature is **fully implemented and ready to use**. Key points:

1. ✅ Policy engine supports `selected_by_creator` scope
2. ✅ Uses `createdById-index` GSI for efficient queries
3. ✅ Automatically filters roles based on `SelectedCreators`
4. ✅ Works for all actions (view, modify, delete)
5. ✅ Supports multiple creators per action
6. ✅ Falls back to scan if GSI unavailable
7. ✅ Includes comprehensive debug logging

**No additional code changes needed** - the feature works out of the box when user assignments are properly configured!

---

## 🔗 Related Files

- `policy_engine.py`: Core implementation of creator filtering
- `overrides.py`: User customization logic with creator selection
- `services/role_retrieval_service.py`: Applies policy engine filters to API responses
- `models/role_repository.py`: Database access layer

---

## 💡 Best Practices

1. **Always populate `createdById`** when creating roles
2. **Use GSI** instead of scan for better performance
3. **Combine with other scopes** for fine-grained control
4. **Monitor CloudWatch logs** for query performance
5. **Use meaningful creator names** in `SelectedCreators` for clarity

---

## 🎉 Conclusion

The creator filter feature provides powerful, granular access control for IAM roles. With the `createdById-index` GSI already in place, the system is production-ready and will efficiently filter roles based on creator assignments.

Deploy with confidence! 🚀
