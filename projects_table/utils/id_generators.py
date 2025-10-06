# -------------------- ID GENERATION --------------------
import os
from datetime import datetime
from botocore.exceptions import ClientError

def generate_unique_display_id(prefix: str, sequences_table) -> str:
    """Generate unique display ID with prefix"""
    upper_prefix = (prefix or "").upper()
    if not upper_prefix:
        raise Exception("Failed to generate ID: missing prefix")
    try:
        update_result = sequences_table.update_item(
            Key={"prefix": upper_prefix},
            UpdateExpression="SET lastValue = if_not_exists(lastValue, :s) + :i, updatedAt = :n",
            ExpressionAttributeValues={
                ":s": 0,
                ":i": 1,
                ":n": datetime.utcnow().isoformat(),
            },
            ReturnValues="UPDATED_NEW",
        )
        current_value = int(update_result["Attributes"]["lastValue"])
        return f"{upper_prefix}-{current_value:05d}"
    except ClientError as e:
        message = e.response.get("Error", {}).get("Message", "Unknown error")
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': {message}")
    except Exception:
        raise Exception(f"Failed to generate ID for prefix '{upper_prefix}': unexpected error")