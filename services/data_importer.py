import os
import json
import io
import datetime
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import UploadFile

from database.models import (
    ConfigUpload, Connection, Threat, FirewallRule,
    NetworkTopology, SystemHealth
)
from services.validators import (
    is_valid_ip, is_valid_port, is_valid_protocol,
    is_valid_action, is_valid_severity, is_valid_bool,
    parse_timestamp, sanitize_string
)

logger = logging.getLogger(__name__)

# Schema fields
CONNECTION_REQUIRED_FIELDS = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'action']
CONNECTION_ALL_FIELDS = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'action',
    'rule_id', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
    'app_name', 'app_category', 'url', 'domain', 'username', 'device_name',
    'device_mac', 'device_os', 'geo_src_country', 'geo_src_city', 'geo_dst_country',
    'geo_dst_city', 'nat_src_ip', 'nat_src_port', 'nat_dst_ip', 'nat_dst_port',
    'threat_detected', 'tcp_flags', 'http_method', 'user_agent', 'decryption_status',
    'interface_in', 'interface_out', 'zone_from', 'zone_to', 'session_end',
    'duration_seconds'
]

THREAT_REQUIRED_FIELDS = ['timestamp', 'threat_name', 'threat_type', 'severity', 'risk_score', 'src_ip', 'dst_ip']
THREAT_ALL_FIELDS = ['timestamp', 'threat_name', 'threat_type', 'severity', 'risk_score', 'src_ip', 'dst_ip',
    'src_port', 'dst_port', 'file_name', 'file_hash', 'file_size', 'file_type', 'malware_family',
    'action_taken', 'rule_id', 'attack_signature', 'cve_id', 'device_name']

FIREWALL_RULE_REQUIRED_FIELDS = ['device_name', 'rule_name', 'rule_position', 'source_ip', 'source_port',
    'dest_ip', 'dest_port', 'protocol', 'action']
FIREWALL_RULE_ALL_FIELDS = ['device_name', 'rule_name', 'rule_position', 'source_ip', 'source_port',
    'dest_ip', 'dest_port', 'protocol', 'action', 'service_name', 'hit_count', 'last_hit', 'is_enabled']

NETWORK_DEVICE_REQUIRED_FIELDS = ['device_name', 'device_type', 'zone', 'ip_address']
NETWORK_DEVICE_ALL_FIELDS = ['device_name', 'device_type', 'zone', 'ip_address', 'ports_open', 'vlan_id', 'subnet', 'is_entry_point']

SYSTEM_HEALTH_REQUIRED_FIELDS = ['timestamp', 'device_name', 'cpu_usage_percent', 'memory_usage_percent', 'active_sessions']
SYSTEM_HEALTH_ALL_FIELDS = ['timestamp', 'device_name', 'cpu_usage_percent', 'memory_usage_percent',
    'active_sessions', 'interface_name', 'interface_status', 'link_speed_mbps']

VALIDATION_CHUNK_SIZE = 25000


def detect_file_type(filename: str, content_type: str | None = None) -> str:
    ext = Path(filename).suffix.lower()
    if ext == '.csv':
        if content_type and 'csv' not in content_type.lower():
            logger.warning('File extension csv but content type %s', content_type)
        return 'csv'
    if ext == '.json':
        if content_type and 'json' not in content_type.lower():
            logger.warning('File extension json but content type %s', content_type)
        return 'json'
    if ext in ['.xlsx', '.xls']:
        if content_type and 'sheet' not in (content_type.lower()):
            logger.warning('File extension xlsx but content type %s', content_type)
        return 'excel'
    raise ValueError(f"Unsupported file extension '{ext}'. Expected .csv, .json, or .xlsx")


def _read_csv_from_upload(file: UploadFile) -> pd.DataFrame:
    file.file.seek(0)
    try:
        df = pd.read_csv(file.file, dtype=str, keep_default_na=False,
                         na_values=['', 'nan', 'null'], encoding='utf-8')
    except pd.errors.ParserError:
        # Ragged CSV (e.g. Palo Alto logs where THREAT rows have extra columns).
        # Re-read the raw text, determine max columns, and pad shorter rows.
        file.file.seek(0)
        try:
            raw_text = file.file.read().decode('utf-8')
        except UnicodeDecodeError:
            file.file.seek(0)
            raw_text = file.file.read().decode('latin-1')
        import csv as _csv
        from io import StringIO
        reader = _csv.reader(StringIO(raw_text))
        all_rows = list(reader)
        if not all_rows:
            return pd.DataFrame()
        header = all_rows[0]
        max_cols = max(len(r) for r in all_rows)
        # Extend header with numbered extras if needed
        extra_headers = [f'_extra_{i}' for i in range(len(header), max_cols)]
        full_header = header + extra_headers
        # Pad shorter rows
        padded = []
        for r in all_rows[1:]:
            padded.append(r + [''] * (max_cols - len(r)))
        df = pd.DataFrame(padded, columns=full_header, dtype=str)
        df = df.replace({'': None, 'nan': None, 'null': None})
        return df
    except UnicodeDecodeError:
        file.file.seek(0)
        df = pd.read_csv(file.file, dtype=str, keep_default_na=False,
                         na_values=['', 'nan', 'null'], encoding='latin-1')
    return df


def _read_json_from_upload(file: UploadFile) -> Dict[str, Any]:
    file.file.seek(0)
    raw_bytes = file.file.read()
    if isinstance(raw_bytes, bytes):
        try:
            raw_text = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raw_text = raw_bytes.decode('latin-1', errors='replace')
    else:
        raw_text = str(raw_bytes)
    payload = json.loads(raw_text)
    if not isinstance(payload, dict):
        raise ValueError('JSON upload must be an object with top-level arrays')
    return payload


def _read_excel_from_upload(file: UploadFile) -> Dict[str, pd.DataFrame]:
    file.file.seek(0)
    try:
        xls = pd.ExcelFile(file.file, engine='openpyxl')
    except Exception as exc:
        raise ValueError(f'Unable to parse Excel file: {exc}')

    sheets = {}
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str, keep_default_na=False, na_values=['', 'nan', 'null'])
        sheets[sheet_name.strip().lower()] = df
    return sheets


def _ensure_fields(df: pd.DataFrame, required: List[str], dataset_name: str) -> None:
    missing = [c for c in required if c not in map(str.lower, df.columns)]
    if missing:
        raise ValueError(f"{dataset_name} is missing required columns: {missing}")


def _sanitize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip() for c in df.columns]
    return df


# ── Vendor CSV auto-detection and normalization ──────────────────────────────

# Palo Alto log columns → our standard schema
_PALOALTO_COL_MAP = {
    'receive time':        'timestamp',
    'generate time':       'timestamp',
    'source address':      'src_ip',
    'destination address': 'dst_ip',
    'source port':         'src_port',
    'destination port':    'dst_port',
    'protocol':            'protocol',
    'action':              'action',
    'rule name':           'rule_id',
    'application':         'app_name',
    'source zone':         'zone_from',
    'destination zone':    'zone_to',
    'source user':         'username',
    'device name':         'device_name',
    'bytes sent':          'bytes_sent',
    'bytes received':      'bytes_received',
    'packets sent':        'packets_sent',
    'packets received':    'packets_received',
    'nat source ip':       'nat_src_ip',
    'nat source port':     'nat_src_port',
    'nat destination ip':  'nat_dst_ip',
    'nat destination port':'nat_dst_port',
    'inbound interface':   'interface_in',
    'outbound interface':  'interface_out',
    'session end reason':  'session_end_reason',
}

# FortiGate syslog CSV columns → our standard schema
_FORTINET_COL_MAP = {
    'date':       'timestamp',
    'time':       '_time_part',
    'srcip':      'src_ip',
    'dstip':      'dst_ip',
    'srcport':    'src_port',
    'dstport':    'dst_port',
    'proto':      'protocol',
    'action':     'action',
    'policyid':   'rule_id',
    'app':        'app_name',
    'srcintf':    'zone_from',
    'dstintf':    'zone_to',
    'user':       'username',
    'devname':    'device_name',
    'sentbyte':   'bytes_sent',
    'rcvdbyte':   'bytes_received',
    'sentpkt':    'packets_sent',
    'rcvdpkt':    'packets_received',
}

# Cisco ASA syslog CSV columns → our standard schema
_CISCO_COL_MAP = {
    'timestamp':        'timestamp',
    'date/time':        'timestamp',
    'src ip':           'src_ip',
    'source ip':        'src_ip',
    'dst ip':           'dst_ip',
    'destination ip':   'dst_ip',
    'src port':         'src_port',
    'source port':      'src_port',
    'dst port':         'dst_port',
    'destination port': 'dst_port',
    'protocol':         'protocol',
    'action':           'action',
    'acl name':         'rule_id',
    'access-group':     'rule_id',
    'interface_in':     'interface_in',
    'interface_out':    'interface_out',
}


def _detect_vendor_csv(columns: List[str]) -> str:
    """Detect vendor from CSV column names. Returns 'paloalto', 'fortinet', 'cisco', or 'standard'."""
    lower_cols = {c.lower() for c in columns}
    # Palo Alto: has 'Source Address', 'Destination Address', 'Virtual System'
    if 'source address' in lower_cols and 'destination address' in lower_cols:
        return 'paloalto'
    # FortiGate: has 'srcip', 'dstip', 'devname'
    if 'srcip' in lower_cols and 'dstip' in lower_cols:
        return 'fortinet'
    # Cisco: has 'src ip' or 'acl name'
    if ('src ip' in lower_cols or 'source ip' in lower_cols) and ('acl name' in lower_cols or 'access-group' in lower_cols):
        return 'cisco'
    return 'standard'


def _normalize_vendor_csv(df: pd.DataFrame, vendor: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Normalize a vendor-specific CSV into standard connection and threat records.
    Returns {'connections': [...], 'threats': [...]}.
    """
    col_map = {
        'paloalto': _PALOALTO_COL_MAP,
        'fortinet': _FORTINET_COL_MAP,
        'cisco':    _CISCO_COL_MAP,
    }.get(vendor, {})

    # Build rename mapping (first match wins for duplicate targets like 'timestamp')
    rename = {}
    used_targets = set()
    lower_to_orig = {c.lower(): c for c in df.columns}
    for vendor_col, std_col in col_map.items():
        if vendor_col in lower_to_orig and std_col not in used_targets:
            rename[lower_to_orig[vendor_col]] = std_col
            used_targets.add(std_col)

    df_renamed = df.rename(columns=rename)

    connections = []
    threats = []

    # Detect log type column (Palo Alto 'Type' column splits TRAFFIC vs THREAT)
    type_col = None
    for c in df_renamed.columns:
        if c.lower() == 'type':
            type_col = c
            break

    for _, row in df_renamed.iterrows():
        record = {k: (v if pd.notna(v) and str(v).strip() != '' else None) for k, v in row.items()}
        log_type = str(record.get(type_col, '') or '').upper() if type_col else 'TRAFFIC'

        if log_type == 'THREAT':
            # Build a threat record
            threat = {
                'timestamp':   record.get('timestamp'),
                'src_ip':      record.get('src_ip'),
                'dst_ip':      record.get('dst_ip'),
                'device_name': record.get('device_name'),
                'threat_type': 'vulnerability',
                'threat_name': 'Unknown Threat',
                'severity':    'medium',
                'risk_score':  5,
            }

            # Palo Alto THREAT rows have extra fields that shift column alignment.
            # Threat name and severity are typically found in known "wrong" columns
            # (e.g. 'Traffic Sequence Number' and 'Order of Frequency' columns)
            # because THREAT log type injects extra fields before these.
            if vendor == 'paloalto':
                # Check known shifted positions for threat data
                _pa_threat_fields = ['Traffic Sequence Number', 'Order of Frequency',
                                     'traffic sequence number', 'order of frequency']
                for c in df_renamed.columns:
                    if c in _pa_threat_fields:
                        val = record.get(c)
                        if val and str(val).strip():
                            sv = str(val).strip().lower()
                            if sv in ('critical', 'high', 'medium', 'low', 'informational'):
                                threat['severity'] = sv
                                threat['risk_score'] = {'critical': 9, 'high': 7, 'medium': 5, 'low': 2, 'informational': 1}.get(sv, 5)
                            elif not sv.replace('.', '').isdigit() and len(str(val).strip()) > 3:
                                threat['threat_name'] = str(val).strip()
                # Also check _extra_ columns for additional data
                for c in df_renamed.columns:
                    if c.startswith('_extra_'):
                        val = record.get(c)
                        if val and str(val).strip():
                            sv = str(val).strip().lower()
                            if sv in ('critical', 'high', 'medium', 'low', 'informational'):
                                threat['severity'] = sv
                                threat['risk_score'] = {'critical': 9, 'high': 7, 'medium': 5, 'low': 2, 'informational': 1}.get(sv, 5)

            # Fallback: scan all values for severity and threat name
            if threat['threat_name'] == 'Unknown Threat':
                raw_values = [str(v) for v in row.values if pd.notna(v) and str(v).strip() not in ('', '0')]
                for val in raw_values:
                    vl = val.lower()
                    if vl in ('critical', 'high', 'medium', 'low'):
                        threat['severity'] = vl
                        threat['risk_score'] = {'critical': 9, 'high': 7, 'medium': 5, 'low': 2}.get(vl, 5)
                for val in raw_values:
                    if len(val) > 10 and not val.replace('.', '').replace('/', '').replace(':', '').isdigit():
                        if val.lower() not in ('tcp', 'udp', 'icmp', 'allow', 'deny', 'drop', 'alert',
                                               'from-policy', 'threat', 'vulnerability', 'start', 'end'):
                            if val not in (record.get('src_ip', ''), record.get('dst_ip', ''),
                                           record.get('device_name', ''), record.get('timestamp', '')):
                                threat['threat_name'] = val
                                break

            # Look for threat type in 'Threat/Content Type' column
            for c in df.columns:
                cl = c.lower()
                if 'threat' in cl and 'content' in cl:
                    raw_tc = record.get(c) or record.get(rename.get(c, c))
                    if raw_tc and str(raw_tc).strip():
                        threat['threat_type'] = str(raw_tc).strip()

            # Map action for threats
            action = str(record.get('action', '') or '').lower()
            if action in ('alert', 'allow'):
                threat['threat_type'] = threat.get('threat_type', 'vulnerability')

            threats.append(threat)
        else:
            # TRAFFIC or default: build a connection record
            conn = {
                'timestamp':    record.get('timestamp'),
                'src_ip':       record.get('src_ip'),
                'dst_ip':       record.get('dst_ip'),
                'src_port':     record.get('src_port'),
                'dst_port':     record.get('dst_port'),
                'protocol':     record.get('protocol'),
                'action':       record.get('action'),
                'rule_id':      record.get('rule_id'),
                'app_name':     record.get('app_name'),
                'zone_from':    record.get('zone_from'),
                'zone_to':      record.get('zone_to'),
                'username':     record.get('username'),
                'device_name':  record.get('device_name'),
                'bytes_sent':   record.get('bytes_sent'),
                'bytes_received': record.get('bytes_received'),
                'packets_sent':   record.get('packets_sent'),
                'packets_received': record.get('packets_received'),
                'nat_src_ip':   record.get('nat_src_ip'),
                'nat_src_port': record.get('nat_src_port'),
                'nat_dst_ip':   record.get('nat_dst_ip'),
                'nat_dst_port': record.get('nat_dst_port'),
                'interface_in': record.get('interface_in'),
                'interface_out': record.get('interface_out'),
            }
            # Determine threat_detected from action or port
            action = str(conn.get('action', '') or '').lower()
            dst_port = conn.get('dst_port')
            try:
                dst_port_int = int(dst_port) if dst_port else None
            except (ValueError, TypeError):
                dst_port_int = None
            risky_ports = {21, 23, 25, 445, 1433, 3306, 3389, 5432}
            conn['threat_detected'] = (
                action in ('alert', 'drop', 'reset-both', 'reset-client', 'reset-server')
                or (dst_port_int in risky_ports and action == 'allow')
            )
            connections.append(conn)

    return {'connections': connections, 'threats': threats}



def _safe_int(v: Any) -> int | None:
    v = sanitize_string(v)
    if v is None:
        return None
    try:
        return int(float(v))
    except Exception:
        raise ValueError(f"Unable to parse integer value '{v}'")


def _safe_float(v: Any) -> float | None:
    v = sanitize_string(v)
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        raise ValueError(f"Unable to parse float value '{v}'")


def _safe_bool(v: Any) -> bool | None:
    if v is None or (isinstance(v, str) and v.strip() == ''):
        return None
    return is_valid_bool(v)


def _validate_connection_row(record: Dict[str, Any], row_number: int,
                             errors: List[Dict[str, Any]],
                             warnings: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    row = {}

    for field in CONNECTION_ALL_FIELDS:
        raw = record.get(field, None)
        if raw is None and field in record:
            raw = record[field]

        if field == 'timestamp':
            try:
                row['timestamp'] = parse_timestamp(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('src_ip', 'dst_ip', 'nat_src_ip', 'nat_dst_ip'):
            try:
                row[field] = is_valid_ip(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('src_port', 'dst_port', 'nat_src_port', 'nat_dst_port'):
            try:
                row[field] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'protocol':
            try:
                row['protocol'] = is_valid_protocol(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': 'protocol', 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'action':
            try:
                row['action'] = is_valid_action(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': 'action', 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('bytes_sent', 'bytes_received', 'packets_sent', 'packets_received', 'duration_seconds'):
            try:
                row[field] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'threat_detected':
            try:
                row['threat_detected'] = _safe_bool(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'session_end':
            try:
                row['session_end'] = parse_timestamp(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        else:
            row[field] = sanitize_string(raw)

    for required in CONNECTION_REQUIRED_FIELDS:
        if row.get(required) in (None, ''):
            errors.append({'row': row_number, 'field': required, 'value': record.get(required), 'reason': 'Required field missing or invalid'})
            return None

    # Apply defaults for non-nullable fields that may be missing from the upload
    _conn_defaults = {
        'bytes_sent': 0, 'bytes_received': 0,
        'packets_sent': 0, 'packets_received': 0,
        'threat_detected': False,
    }
    for field_name, default_val in _conn_defaults.items():
        if row.get(field_name) is None:
            row[field_name] = default_val

    # warnings for optional missing values
    for optional in set(CONNECTION_ALL_FIELDS) - set(CONNECTION_REQUIRED_FIELDS):
        if row.get(optional) is None:
            warnings.append({'row': row_number, 'field': optional, 'reason': 'optional field is empty'})

    return row


def _validate_threat_row(record: Dict[str, Any], row_number: int,
                         errors: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    row = {}
    for field in THREAT_ALL_FIELDS:
        raw = record.get(field, None)
        if field == 'timestamp':
            try:
                row['timestamp'] = parse_timestamp(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('src_ip', 'dst_ip'):
            try:
                row[field] = is_valid_ip(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'severity':
            try:
                row['severity'] = is_valid_severity(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'risk_score':
            try:
                row['risk_score'] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('file_size',):
            try:
                row[field] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        else:
            row[field] = sanitize_string(raw)

    for required in THREAT_REQUIRED_FIELDS:
        if row.get(required) in (None, ''):
            errors.append({'row': row_number, 'field': required, 'value': record.get(required), 'reason': 'Required field missing or invalid'})
            return None

    for optional in set(THREAT_ALL_FIELDS) - set(THREAT_REQUIRED_FIELDS):
        if row.get(optional) is None:
            warnings.append({'row': row_number, 'field': optional, 'reason': 'optional field is empty'})

    return row


def _validate_firewall_rule_row(record: Dict[str, Any], row_number: int,
                                errors: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    row = {}
    for field in FIREWALL_RULE_ALL_FIELDS:
        raw = record.get(field, None)
        if field in ('rule_position', 'hit_count'):
            try:
                row[field] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'last_hit':
            try:
                row['last_hit'] = parse_timestamp(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'is_enabled':
            try:
                row['is_enabled'] = _safe_bool(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'protocol':
            try:
                row['protocol'] = is_valid_protocol(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'action':
            try:
                row['action'] = is_valid_action(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        else:
            row[field] = sanitize_string(raw)

    for required in FIREWALL_RULE_REQUIRED_FIELDS:
        if row.get(required) in (None, ''):
            errors.append({'row': row_number, 'field': required, 'value': record.get(required), 'reason': 'Required field missing or invalid'})
            return None

    for optional in set(FIREWALL_RULE_ALL_FIELDS) - set(FIREWALL_RULE_REQUIRED_FIELDS):
        if row.get(optional) is None:
            warnings.append({'row': row_number, 'field': optional, 'reason': 'optional field is empty'})

    return row


def _validate_network_device_row(record: Dict[str, Any], row_number: int,
                                  errors: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    row = {}
    for field in NETWORK_DEVICE_ALL_FIELDS:
        raw = record.get(field, None)
        if field == 'ip_address':
            try:
                row['ip_address'] = is_valid_ip(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'ports_open':
            raw2 = sanitize_string(raw)
            if raw2:
                try:
                    row['ports_open'] = [int(p.strip()) for p in raw2.split(',') if p.strip()]
                except Exception as exc:
                    errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': f'ports_open parse error {exc}'})
                    return None
            else:
                row['ports_open'] = []
        elif field == 'vlan_id':
            try:
                row['vlan_id'] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'subnet':
            row['subnet'] = sanitize_string(raw)
        elif field == 'is_entry_point':
            try:
                row['is_entry_point'] = _safe_bool(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        else:
            row[field] = sanitize_string(raw)

    for required in NETWORK_DEVICE_REQUIRED_FIELDS:
        if row.get(required) in (None, ''):
            errors.append({'row': row_number, 'field': required, 'value': record.get(required), 'reason': 'Required field missing or invalid'})
            return None

    for optional in set(NETWORK_DEVICE_ALL_FIELDS) - set(NETWORK_DEVICE_REQUIRED_FIELDS):
        if row.get(optional) is None:
            warnings.append({'row': row_number, 'field': optional, 'reason': 'optional field is empty'})

    return row


def _validate_system_health_row(record: Dict[str, Any], row_number: int,
                                errors: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    row = {}
    for field in SYSTEM_HEALTH_ALL_FIELDS:
        raw = record.get(field, None)
        if field == 'timestamp':
            try:
                row['timestamp'] = parse_timestamp(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field in ('cpu_usage_percent', 'memory_usage_percent'):
            try:
                row[field] = _safe_float(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'active_sessions':
            try:
                row['active_sessions'] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        elif field == 'link_speed_mbps':
            try:
                row['link_speed_mbps'] = _safe_int(raw)
            except ValueError as exc:
                errors.append({'row': row_number, 'field': field, 'value': raw, 'reason': str(exc)})
                return None
        else:
            row[field] = sanitize_string(raw)

    for required in SYSTEM_HEALTH_REQUIRED_FIELDS:
        if row.get(required) in (None, ''):
            errors.append({'row': row_number, 'field': required, 'value': record.get(required), 'reason': 'Required field missing or invalid'})
            return None

    for optional in set(SYSTEM_HEALTH_ALL_FIELDS) - set(SYSTEM_HEALTH_REQUIRED_FIELDS):
        if row.get(optional) is None:
            warnings.append({'row': row_number, 'field': optional, 'reason': 'optional field is empty'})

    return row


def _validate_dataset(dataset_name: str, records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    cleaned = []
    errors = []
    warnings = []

    validator = {
        'connections': _validate_connection_row,
        'threats': _validate_threat_row,
        'firewall_rules': _validate_firewall_rule_row,
        'network_topology': _validate_network_device_row,
        'system_health': _validate_system_health_row,
    }.get(dataset_name)

    if validator is None:
        raise ValueError(f'No validator for dataset {dataset_name}')

    for idx, record in enumerate(records, start=1):
        normalized_record = {k.strip(): v for k, v in record.items()} if isinstance(record, dict) else {}
        result = validator(normalized_record, idx, errors, warnings)
        if result is not None:
            cleaned.append(result)

    return cleaned, errors, warnings


async def _bulk_insert(session: AsyncSession, model, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    # Only keep keys that correspond to actual model columns
    valid_cols = {c.key for c in model.__table__.columns}
    filtered = [{k: v for k, v in row.items() if k in valid_cols} for row in rows]
    stmt = insert(model).values(filtered)
    await session.execute(stmt)
    return len(filtered)


def _excel_sheet_map(sheet_name: str) -> str:
    normalized = sheet_name.strip().lower()
    if normalized in ['connections', 'connections ']:
        return 'connections'
    if normalized in ['threats', 'threats ']:
        return 'threats'
    if normalized in ['firewall_rules', 'firewall rules', 'firewall_rules ']:
        return 'firewall_rules'
    if normalized in ['network_devices', 'network_devices ', 'network_topology']:
        return 'network_topology'
    if normalized in ['system_health', 'system_health ']:
        return 'system_health'
    return ''


async def parse_and_validate_file(file: UploadFile) -> Dict[str, Any]:
    file_type = detect_file_type(file.filename, file.content_type)
    data: Dict[str, Any] = {}

    try:
        if file_type == 'csv':
            df = _read_csv_from_upload(file)
            df = _sanitize_columns(df)

            # Auto-detect vendor CSV format
            vendor = _detect_vendor_csv(list(df.columns))
            if vendor != 'standard':
                logger.info('Detected %s vendor CSV format — normalizing columns', vendor)
                normalized = _normalize_vendor_csv(df, vendor)
                data['connections'] = normalized.get('connections', [])
                data['threats'] = normalized.get('threats', [])
            else:
                _ensure_fields(df, CONNECTION_REQUIRED_FIELDS, 'connections')
                data['connections'] = df.to_dict(orient='records')
        elif file_type == 'json':
            payload = _read_json_from_upload(file)
            for key in ['connections', 'threats', 'firewall_rules', 'network_topology', 'system_health']:
                raw = payload.get(key, [])
                if raw is None:
                    raw = []
                if not isinstance(raw, list):
                    raise ValueError(f"JSON array '{key}' must be a list")
                data[key] = raw
        else:
            sheets = _read_excel_from_upload(file)
            data = {'connections': [], 'threats': [], 'firewall_rules': [], 'network_topology': [], 'system_health': []}
            for sheet_name, df in sheets.items():
                target = _excel_sheet_map(sheet_name)
                if not target:
                    continue
                df = _sanitize_columns(df)
                data[target] = df.to_dict(orient='records')

        report = {
            'connections': {'valid': [], 'errors': [], 'warnings': []},
            'threats': {'valid': [], 'errors': [], 'warnings': []},
            'firewall_rules': {'valid': [], 'errors': [], 'warnings': []},
            'network_topology': {'valid': [], 'errors': [], 'warnings': []},
            'system_health': {'valid': [], 'errors': [], 'warnings': []}
        }

        overall_errors = []
        overall_warnings = []
        all_cleaned = {}

        for dataset_name in report.keys():
            raw_records = data.get(dataset_name, [])
            cleaned, errors, warnings = _validate_dataset(dataset_name, raw_records)
            all_cleaned[dataset_name] = cleaned
            report[dataset_name]['valid'] = cleaned
            report[dataset_name]['errors'] = errors
            report[dataset_name]['warnings'] = warnings

            for e in errors:
                e['dataset'] = dataset_name
                overall_errors.append(e)
            for w in warnings:
                w['dataset'] = dataset_name
                overall_warnings.append(w)

        return {
            'file_type': file_type,
            'total_rows': sum(len(data.get(k, [])) for k in report.keys()),
            'valid_rows': sum(len(report[k]['valid']) for k in report.keys()),
            'invalid_rows': sum(len(report[k]['errors']) for k in report.keys()),
            'errors': overall_errors,
            'warnings': overall_warnings,
            'detailed': report,
            'cleaned_data': all_cleaned
        }
    except Exception as exc:
        logger.error('Failed to parse and validate file %s: %s', file.filename, exc)
        raise


async def ingest_data_file(file: UploadFile, db: AsyncSession) -> Dict[str, Any]:
    # 1. Create tracking row in config_uploads
    file.file.seek(0, io.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > 500 * 1024 * 1024:
        raise ValueError('File size exceeds 500MB limit')

    config_upload = ConfigUpload(
        filename=file.filename,
        file_size=file_size,
        vendor='universal',
        ingestion_status='processing',
        progress_percent=0,
        configs_processed=0,
        errors_count=0,
        warnings_count=0,
        unsupported_count=0,
        error_messages=[]
    )
    db.add(config_upload)
    await db.commit()
    await db.refresh(config_upload)

    validation_result = None
    try:
        validation_result = await parse_and_validate_file(file)
        cleaned = validation_result['cleaned_data']

        inserted_counts = {
            'connections': 0,
            'threats': 0,
            'firewall_rules': 0,
            'network_topology': 0,
            'system_health': 0
        }

        if cleaned['connections']:
            inserted_counts['connections'] = await _bulk_insert(db, Connection, cleaned['connections'])
            config_upload.progress_percent = min(100, int((inserted_counts['connections'] / max(1, len(cleaned['connections']))) * 20))

        if cleaned['threats']:
            inserted_counts['threats'] = await _bulk_insert(db, Threat, cleaned['threats'])
            config_upload.progress_percent = min(100, config_upload.progress_percent + 15)

        if cleaned['firewall_rules']:
            inserted_counts['firewall_rules'] = await _bulk_insert(db, FirewallRule, cleaned['firewall_rules'])
            config_upload.progress_percent = min(100, config_upload.progress_percent + 20)

        if cleaned['network_topology']:
            inserted_counts['network_topology'] = await _bulk_insert(db, NetworkTopology, cleaned['network_topology'])
            config_upload.progress_percent = min(100, config_upload.progress_percent + 20)

        if cleaned['system_health']:
            inserted_counts['system_health'] = await _bulk_insert(db, SystemHealth, cleaned['system_health'])
            config_upload.progress_percent = min(100, config_upload.progress_percent + 20)

        config_upload.configs_processed = sum(inserted_counts.values())
        config_upload.errors_count = len(validation_result['errors'])
        config_upload.warnings_count = len(validation_result['warnings'])
        config_upload.ingestion_status = 'completed'
        config_upload.progress_percent = 100
        config_upload.error_messages = validation_result['errors']
        config_upload.completed_at = datetime.datetime.utcnow()
        db.add(config_upload)
        await db.commit()

        return {
            'status': 'success',
            'upload_id': str(config_upload.id),
            'file_type': validation_result['file_type'],
            'total_rows': validation_result['total_rows'],
            'processed_rows': config_upload.configs_processed,
            'errors_count': config_upload.errors_count,
            'warnings_count': config_upload.warnings_count,
            'errors': validation_result['errors'],
            'warnings': validation_result['warnings'],
            'inserted_counts': inserted_counts,
            'config_upload_status': config_upload.ingestion_status
        }
    except Exception as exc:
        logger.exception('Data ingest failed for %s', file.filename)
        config_upload.ingestion_status = 'failed'
        config_upload.error_messages = [{'reason': str(exc)}]
        config_upload.progress_percent = 0
        await db.commit()
        raise


async def validate_upload_file(file: UploadFile) -> Dict[str, Any]:
    file.file.seek(0, io.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > 500 * 1024 * 1024:
        raise ValueError('File size exceeds 500MB limit')

    result = await parse_and_validate_file(file)
    return {
        'valid': result['invalid_rows'] == 0,
        'total_rows': result['total_rows'],
        'valid_rows': result['valid_rows'],
        'invalid_rows': result['invalid_rows'],
        'errors': result['errors'],
        'warnings': result['warnings']
    }
