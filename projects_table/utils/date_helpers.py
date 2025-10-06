# -------------------- DATE UTILITIES --------------------
from datetime import datetime

def format_date(iso_datetime_string):
    """Format ISO datetime string to MM-DD-YYYY format"""
    try:
        return datetime.fromisoformat(iso_datetime_string).strftime("%m-%d-%Y")
    except Exception:
        return iso_datetime_string