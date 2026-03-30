import csv
import io
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from utils.tcp_flags import parse_tcp_flags

logger = logging.getLogger(__name__)

class PaloAltoParser:
    def __init__(self):
        pass

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parses a Palo Alto syslog message.
        Palo Alto logs are CSV formatted.
        """
        try:
            # Syslog header is usually stripped or handled by the listener
            # We assume the message starts with the log type or is just the CSV part
            if "," not in message:
                return {}
                
            f = io.StringIO(message)
            reader = csv.reader(f)
            fields = next(reader)
            
            log_type = fields[3] # TRAFFIC, THREAT, SYSTEM, CONFIG, etc.
            
            if log_type == 'TRAFFIC':
                return self._parse_traffic(fields)
            elif log_type == 'THREAT':
                return self._parse_threat(fields)
            elif log_type == 'SYSTEM':
                return self._parse_system(fields)
            
            return {}
        except Exception as e:
            logger.error(f"Error parsing Palo Alto message: {e}")
            return {}

    def _parse_traffic(self, fields: list) -> Dict[str, Any]:
        # Based on PAN-OS Syslog Field Descriptions
        try:
            data = {
                "type": "connection",
                "timestamp": self._parse_date(fields[6]),
                "src_ip": fields[7],
                "dst_ip": fields[8],
                "src_port": int(fields[24]) if fields[24] else None,
                "dst_port": int(fields[25]) if fields[25] else None,
                "protocol": fields[29],
                "action": fields[30],
                "rule_id": fields[10],
                "interface_in": fields[11],
                "interface_out": fields[12],
                "zone_from": fields[13],
                "zone_to": fields[14],
                "bytes_sent": int(fields[31]) if fields[31] else 0,
                "bytes_received": int(fields[32]) if fields[32] else 0,
                "packets_sent": int(fields[33]) if fields[33] else 0,
                "packets_received": int(fields[34]) if fields[34] else 0,
                "tcp_flags": parse_tcp_flags(fields[42]), # field 42 is flags
                "app_name": fields[23],
                "username": fields[17],
                "device_name": fields[18],
                "nat_src_ip": fields[43],
                "nat_dst_ip": fields[44],
                "nat_src_port": int(fields[45]) if fields[45] else None,
                "nat_dst_port": int(fields[46]) if fields[46] else None,
                "decryption_status": fields[55], # decrypt_mirror
                "url": fields[61] if len(fields) > 61 else None,
                "user_agent": fields[63] if len(fields) > 63 else None,
            }
            # Extract domain from URL if possible
            if data["url"] and "//" in data["url"]:
                data["domain"] = data["url"].split("//")[1].split("/")[0]
            
            # Extract HTTP method if present in URL
            if data["url"] and " " in data["url"]:
                data["http_method"] = data["url"].split(" ")[0]
            
            logger.debug(f"Extracted app_name={data['app_name']} from field[23]")
            return data
        except (IndexError, ValueError) as e:
            logger.warning(f"Malformed Palo Alto TRAFFIC log: {e}")
            return {}

    def _parse_threat(self, fields: list) -> Dict[str, Any]:
        try:
            data = {
                "type": "threat",
                "timestamp": self._parse_date(fields[6]),
                "src_ip": fields[7],
                "dst_ip": fields[8],
                "device_name": fields[18],
                "threat_name": fields[23],
                "severity": fields[24],
                "threat_type": fields[30],
                "risk_score": int(fields[32]) if fields[32] else 0,
                "file_hash": fields[29],
                "file_name": fields[40] if len(fields) > 40 else None,
                "file_size": int(fields[41]) if len(fields) > 41 and fields[41] else 0,
                "file_type": fields[42] if len(fields) > 42 else None,
            }
            return data
        except (IndexError, ValueError) as e:
            logger.warning(f"Malformed Palo Alto THREAT log: {e}")
            return {}

    def _parse_system(self, fields: list) -> Dict[str, Any]:
        try:
            data = {
                "type": "admin_audit",
                "timestamp": self._parse_date(fields[6]),
                "device_name": fields[18],
                "admin_username": fields[11],
                "action_type": fields[12],
                "change_before": fields[13],
                "change_after": fields[14],
            }
            return data
        except (IndexError, ValueError) as e:
            logger.warning(f"Malformed Palo Alto SYSTEM log: {e}")
            return {}

    def _parse_date(self, date_str: str) -> datetime:
        try:
            return datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S')
        except ValueError:
            return datetime.utcnow()
