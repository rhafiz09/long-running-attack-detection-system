import logging
from datetime import datetime, timezone
from typing import Any, Optional, Dict
import pandas as pd

logger = logging.getLogger(__name__)


def clean_empty_string(val: Any) -> Optional[Any]:
    """
    Data Type Conversion Utility:
    Converts empty strings (""), whitespace, or "null"/"nan" strings to NULL (None).
    """
    if val is None:
        return None

    if isinstance(val, float) and pd.isna(val):
        return None

    if isinstance(val, str):
        stripped = val.strip()
        if not stripped or stripped.lower() in ("null", "nan", "none", ""):
            return None
        return stripped

    return val


def parse_log_date(val: Any) -> Optional[datetime]:
    """
    Data Type Conversion Utility:
    Handles scientific notation (e.g., 1.78E+12 from CSV export) and converts it into
    standard datetime format (UTC Timestamp).
    Also supports standard date strings (ISO 8601, "MM/DD/YYYY HH:MM:SS am/pm").
    """
    val = clean_empty_string(val)
    if val is None:
        return None

    # Handle direct numeric timestamps (e.g. floats or ints)
    if isinstance(val, (int, float)):
        try:
            num = float(val)
            # If greater than 10^11, assume epoch milliseconds (e.g. 1772633968263)
            if num > 1e11:
                return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
            elif num > 1e9:
                return datetime.fromtimestamp(num, tz=timezone.utc)
        except Exception as e:
            logger.debug(f"Numeric timestamp conversion failed for {val}: {e}")

    # Handle string representations (scientific notation or date strings)
    if isinstance(val, str):
        # 1. Try checking if it's scientific notation or numeric string
        try:
            num = float(val)
            if num > 1e11:
                return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
            elif num > 1e9:
                return datetime.fromtimestamp(num, tz=timezone.utc)
        except ValueError:
            pass

        # 2. Try parsing with pandas to_datetime which is highly versatile for log formats
        try:
            dt = pd.to_datetime(val, errors="raise")
            if dt.tz is None:
                dt = dt.tz_localize(timezone.utc)
            return dt.to_pydatetime()
        except Exception as e:
            logger.debug(f"String date parsing failed for '{val}': {e}")

    # Fallback to current UTC time if parsing fails or return None
    logger.warning(f"Unrecognized Log Date format: '{val}'. Defaulting to None.")
    return None


def clean_log_record(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes an entire row dictionary from CSV or raw payload.
    1. STRICTLY maps and converts the 7 core AI model columns.
    2. Packages the remaining 100+ flexible columns cleanly into the JSONB additional_data dict.
    """
    # Core column mapping (supports both CSV headers and direct attribute names)
    log_date_val = parse_log_date(
        row_dict.get("Log Date") or row_dict.get("log_date")
    )
    if not log_date_val:
        # Default to current UTC if missing in sample data to prevent NOT NULL constraint failure
        log_date_val = datetime.now(timezone.utc)

    ip_origin = clean_empty_string(
        row_dict.get("IP Address (Origin)") or row_dict.get("ip_origin")
    )
    ip_impacted = clean_empty_string(
        row_dict.get("IP Address (Impacted)") or row_dict.get("ip_impacted")
    )

    # Clean port impacted (convert string integer to int if possible)
    port_val = clean_empty_string(
        row_dict.get("TCP/UDP Port (Impacted)") or row_dict.get("port_impacted")
    )
    port_impacted = None
    if port_val is not None:
        try:
            port_impacted = int(float(port_val))
            if port_impacted < 0 or port_impacted > 65535:
                port_impacted = None
        except (ValueError, TypeError):
            port_impacted = None

    zone_origin = clean_empty_string(
        row_dict.get("Zone (Origin)") or row_dict.get("zone_origin")
    )
    zone_impacted = clean_empty_string(
        row_dict.get("Zone (Impacted)") or row_dict.get("zone_impacted")
    )
    log_source = clean_empty_string(
        row_dict.get("Log Source") or row_dict.get("log_source")
    )

    # Identify core keys to exclude from additional_data
    core_headers = {
        "Log Date", "log_date",
        "IP Address (Origin)", "ip_origin",
        "IP Address (Impacted)", "ip_impacted",
        "TCP/UDP Port (Impacted)", "port_impacted",
        "Zone (Origin)", "zone_origin",
        "Zone (Impacted)", "zone_impacted",
        "Log Source", "log_source",
        "id"
    }

    # Collect all remaining 100+ flexible columns into additional_data
    additional_data: Dict[str, Any] = {}
    for key, value in row_dict.items():
        if key not in core_headers:
            cleaned_val = clean_empty_string(value)
            if cleaned_val is not None:
                additional_data[key] = cleaned_val

    return {
        "log_date": log_date_val,
        "ip_origin": str(ip_origin) if ip_origin else None,
        "ip_impacted": str(ip_impacted) if ip_impacted else None,
        "port_impacted": port_impacted,
        "zone_origin": str(zone_origin) if zone_origin else None,
        "zone_impacted": str(zone_impacted) if zone_impacted else None,
        "log_source": str(log_source) if log_source else None,
        "additional_data": additional_data,
    }


def classify_log_vendor(cleaned_record: Dict[str, Any]) -> str:
    """
    Vendor Classification Engine:
    Inspects log_source and additional_data fields to determine the target vendor table
    ('palo_alto', 'fortinet', or 'fortiwaf').
    """
    log_source = str(cleaned_record.get("log_source") or "").lower()
    additional_data = cleaned_record.get("additional_data") or {}

    vendor_info = str(additional_data.get("Vendor Info") or additional_data.get("vendor_info") or "").lower()
    device_name = str(additional_data.get("Device Name") or additional_data.get("device_name") or "").lower()
    combined_info = f"{log_source} {vendor_info} {device_name}"

    if any(k in combined_info for k in ("fortiwaf", "forti_waf", "waf", "web application firewall")):
        return "fortiwaf"
    elif any(k in combined_info for k in ("fortinet", "fortigate", "fortios", "forti")):
        return "fortinet"
    else:
        # Default fallback to palo_alto
        return "palo_alto"

