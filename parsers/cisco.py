import re
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

class CiscoParser:
    def __init__(self):
        # Regex patterns for ASA logs
        self.built_pattern = re.compile(r'%ASA-6-302013: Built (inbound|outbound) (TCP|UDP) connection \d+ for (\S+):(\S+)/(\d+) \((\S+)/(\d+)\) to (\S+):(\S+)/(\d+) \((\S+)/(\d+)\)')
        self.deny_pattern = re.compile(r'%ASA-4-106023: Deny (tcp|udp) src (\S+):(\S+)/(\d+) dst (\S+):(\S+)/(\d+) by access-group "([^"]+)"')
        self.nat_pattern = re.compile(r'%ASA-6-302020: Built (dynamic|static) (TCP|UDP) translation from (\S+):(\S+)/(\d+) to (\S+):(\S+)/(\d+)')

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parses a Cisco ASA syslog message.
        """
        try:
            if '%ASA-6-302013' in message:
                return self._parse_built(message)
            elif '%ASA-4-106023' in message:
                return self._parse_deny(message)
            elif '%ASA-6-302020' in message:
                return self._parse_nat(message)
            
            return {}
        except Exception as e:
            logger.error(f"Error parsing Cisco message: {e}")
            return {}

    def _parse_built(self, message: str) -> Dict[str, Any]:
        match = self.built_pattern.search(message)
        if not match:
            return {}
        
        groups = match.groups()
        try:
            data = {
                "type": "connection",
                "timestamp": datetime.utcnow(), # ASA logs usually have timestamps in header, assuming handled by listener
                "protocol": groups[1],
                "interface_in": groups[2],
                "src_ip": groups[3],
                "src_port": int(groups[4]),
                "nat_src_ip": groups[5],
                "nat_src_port": int(groups[6]),
                "interface_out": groups[7],
                "dst_ip": groups[8],
                "dst_port": int(groups[9]),
                "nat_dst_ip": groups[10],
                "nat_dst_port": int(groups[11]),
                "action": "allow",
                "app_name": None, # ASA has no native App-ID
            }
            return data
        except (ValueError, IndexError) as e:
            logger.warning(f"Malformed Cisco Built log: {e}")
            return {}

    def _parse_deny(self, message: str) -> Dict[str, Any]:
        match = self.deny_pattern.search(message)
        if not match:
            return {}
            
        groups = match.groups()
        try:
            data = {
                "type": "connection",
                "timestamp": datetime.utcnow(),
                "protocol": groups[0].upper(),
                "interface_in": groups[1],
                "src_ip": groups[2],
                "src_port": int(groups[3]),
                "interface_out": groups[4],
                "dst_ip": groups[5],
                "dst_port": int(groups[6]),
                "rule_id": groups[7],
                "action": "deny",
                "app_name": None,
            }
            return data
        except (ValueError, IndexError) as e:
            logger.warning(f"Malformed Cisco Deny log: {e}")
            return {}

    def _parse_nat(self, message: str) -> Dict[str, Any]:
        match = self.nat_pattern.search(message)
        if not match:
            return {}
            
        groups = match.groups()
        try:
            # This is a NAT mapping message, could be used to update existing connection records
            # For simplicity, we return it as a connection type but marked as NAT
            data = {
                "type": "nat_mapping",
                "timestamp": datetime.utcnow(),
                "protocol": groups[1],
                "interface_in": groups[2],
                "src_ip": groups[3],
                "src_port": int(groups[4]),
                "interface_out": groups[5],
                "nat_src_ip": groups[6],
                "nat_src_port": int(groups[7]),
            }
            return data
        except (ValueError, IndexError) as e:
            logger.warning(f"Malformed Cisco NAT log: {e}")
            return {}
