import ipaddress
import datetime
from typing import Any

VALID_PROTOCOLS = {'tcp', 'udp', 'icmp', 'sctp', 'gre', 'ip', 'any'}
VALID_ACTIONS = {'allow', 'deny', 'drop', 'reject'}
VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}


def sanitize_string(value: Any) -> str | None:
    if value is None:
        return None
    value_str = str(value).strip()
    if value_str == '' or value_str.lower() in {'nan', 'none', 'null', '-'}:
        return None
    return value_str


def is_valid_ip(value: Any) -> str | None:
    value = sanitize_string(value)
    if value is None:
        return None
    if value.lower() in {'any', '0.0.0.0', '::'}:
        return value
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError as exc:
        raise ValueError(f"Invalid IP address '{value}': {exc}")


def is_valid_port(value: Any) -> int | None:
    value = sanitize_string(value)
    if value is None or value.lower() == 'any':
        return None
    if isinstance(value, bool):
        raise ValueError('Boolean is not a valid port')
    try:
        port = int(float(value))
    except Exception:
        raise ValueError(f"Invalid port value '{value}'")
    if not (0 <= port <= 65535):
        raise ValueError(f"Port '{port}' out of range (0-65535)")
    return port


def is_valid_protocol(value: Any) -> str | None:
    value = sanitize_string(value)
    if value is None:
        return None
    normalized = value.lower()
    if normalized not in VALID_PROTOCOLS:
        raise ValueError(f"Protocol '{value}' is not valid. Allowed: {', '.join(sorted(VALID_PROTOCOLS))}")
    return normalized


def is_valid_action(value: Any) -> str | None:
    value = sanitize_string(value)
    if value is None:
        return None
    normalized = value.lower()
    if normalized not in VALID_ACTIONS:
        raise ValueError(f"Action '{value}' is not valid. Allowed: {', '.join(sorted(VALID_ACTIONS))}")
    return normalized


def is_valid_severity(value: Any) -> str | None:
    value = sanitize_string(value)
    if value is None:
        return None
    normalized = value.lower()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(f"Severity '{value}' is not valid. Allowed: {', '.join(sorted(VALID_SEVERITIES))}")
    return normalized


def is_valid_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    value = sanitize_string(value)
    if value is None:
        return None
    val_lower = value.lower()
    if val_lower in {'true', '1', 'yes', 'y', 't'}:
        return True
    if val_lower in {'false', '0', 'no', 'n', 'f'}:
        return False
    raise ValueError(f"Boolean field value '{value}' is invalid")


def parse_timestamp(value: Any) -> datetime.datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time.min)

    val = sanitize_string(value)
    if val is None:
        return None

    # Try some common formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d',
        '%Y/%m/%d %H:%M:%S',
        '%Y/%m/%d %H:%M:%S.%f',
        '%Y/%m/%d',
        '%m/%d/%Y %H:%M:%S',
        '%m/%d/%Y',
        '%d/%m/%Y',
        '%d-%m-%Y',
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(val, fmt)
        except ValueError:
            pass

    # ISO 8601 variant
    try:
        normalized = val.replace('Z', '+00:00')
        return datetime.datetime.fromisoformat(normalized)
    except Exception as exc:
        raise ValueError(f"Invalid timestamp '{value}': {exc}")
