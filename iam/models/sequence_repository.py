"""
Sequence repository for generating display IDs.
"""
from datetime import datetime
from logging_config import create_logger
from .database import SEQUENCES_TBL

logger = create_logger("models.sequence_repository")


def update_sequence_and_get_display(prefix: str) -> str:
    """Generate next sequence number for display ID."""
    result = SEQUENCES_TBL.update_item(
        Key={"prefix": prefix},
        UpdateExpression="SET lastValue = if_not_exists(lastValue, :start) + :step, updatedAt = :ts",
        ExpressionAttributeValues={
            ":start": 0,
            ":step": 1,
            ":ts": datetime.utcnow().isoformat()
        },
        ReturnValues="UPDATED_NEW"
    )
    seq = int(result["Attributes"]["lastValue"])
    return f"{prefix}-{seq:05d}"
