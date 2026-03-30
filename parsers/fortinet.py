import re
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

class FortinetParser:
    def __init__(self):
        # Regex for key=value or key="value"
        self.kv_pattern = re.compile(r'(\w+)=("[^"]*"|\S+)')

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parses a Fortinet syslog message (key-value format).
        """
        try:
            kv_pairs = self.kv_pattern.findall(message)
            raw_data = {k: v.strip('"') for k, v in kv_pairs}
            
            log_type = raw_data.get('type')
            
            if log_type == 'traffic':
                return self._parse_traffic(raw_data)
            elif log_type == 'utm' or 'attack' in raw_data:
                return self._parse_threat(raw_data)
            elif log_type == 'event' and raw_data.get('subtype') == 'system':
                return self._parse_system(raw_data)
                
            return {}
        except Exception as e:
            logger.error(f"Error parsing Fortinet message: {e}")
            return {}

    def _parse_traffic(self, raw: Dict[str, str]) -> Dict[str, Any]:
        try:
            data = {
                "type": "connection",
                "timestamp": self._parse_date(raw.get('date'), raw.get('time')),
                "src_ip": raw.get('srcip'),
                "dst_ip": raw.get('dstip'),
                "src_port": int(raw['srcport']) if raw.get('srcport') else None,
                "dst_port": int(raw['dstport']) if raw.get('dstport') else None,
                "protocol": raw.get('proto'),
                "action": raw.get('utmaction') or raw.get('action'),
                "rule_id": raw.get('policyid'),
                "interface_in": raw.get('srcintf'),
                "interface_out": raw.get('dstintf'),
                "zone_from": raw.get('srczone'),
                "zone_to": raw.get('dstzone'),
                "bytes_sent": int(raw['sentbyte']) if raw.get('sentbyte') else 0,
                "bytes_received": int(raw['rcvdbyte']) if raw.get('rcvdbyte') else 0,
                "packets_sent": int(raw['sentpkt']) if raw.get('sentpkt') else 0,
                "packets_received": int(raw['rcvdpkt']) if raw.get('rcvdpkt') else 0,
                "app_name": raw.get('app') or raw.get('appid'),
                "app_category": raw.get('catdesc') or raw.get('cat'),
                "username": raw.get('user'),
                "device_name": raw.get('devname'),
                "device_mac": raw.get('mac'),
                "device_os": raw.get('osname'),
                "nat_src_ip": raw.get('tranip'),
                "nat_src_port": int(raw['tranport']) if raw.get('tranport') else None,
                "nat_dst_ip": raw.get('transip'),
                "nat_dst_port": int(raw['transport']) if raw.get('transport') else None,
                "decryption_status": raw.get('sslaction'),
                "url": raw.get('url'),
                "domain": raw.get('hostname'),
                "user_agent": raw.get('agent'),
                "http_method": raw.get('method'),
            }
            logger.debug(f"Extracted app_name={data['app_name']} from key 'app'")
            return data
        except (ValueError, KeyError) as e:
            logger.warning(f"Malformed Fortinet traffic log: {e}")
            return {}

    def _parse_threat(self, raw: Dict[str, str]) -> Dict[str, Any]:
        try:
            data = {
                "type": "threat",
                "timestamp": self._parse_date(raw.get('date'), raw.get('time')),
                "src_ip": raw.get('srcip'),
                "dst_ip": raw.get('dstip'),
                "device_name": raw.get('devname'),
                "threat_name": raw.get('attack') or raw.get('threat'),
                "threat_type": raw.get('subtype'),
                "severity": raw.get('level') or raw.get('severity'),
                "risk_score": int(raw['risk']) if raw.get('risk') else 0,
                "file_name": raw.get('filename'),
                "file_size": int(raw['filesize']) if raw.get('filesize') else 0,
                "file_type": raw.get('filetype'),
                "file_hash": raw.get('hash'),
            }
            return data
        except (ValueError, KeyError) as e:
            logger.warning(f"Malformed Fortinet threat log: {e}")
            return {}

    def _parse_system(self, raw: Dict[str, str]) -> Dict[str, Any]:
        try:
            data = {
                "type": "admin_audit",
                "timestamp": self._parse_date(raw.get('date'), raw.get('time')),
                "device_name": raw.get('devname'),
                "admin_username": raw.get('user'),
                "action_type": raw.get('action'),
                "change_before": raw.get('ui'),
                "change_after": raw.get('msg'),
            }
            return data
        except (ValueError, KeyError) as e:
            logger.warning(f"Malformed Fortinet system log: {e}")
            return {}

    def _parse_date(self, date_str: str, time_str: str) -> datetime:
        if not date_str or not time_str:
            return datetime.utcnow()
        try:
            return datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return datetime.utcnow()
