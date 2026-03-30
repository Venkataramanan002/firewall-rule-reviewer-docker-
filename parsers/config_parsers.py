import re
import uuid
import random
import datetime
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerable port metadata used for synthetic threat generation
# ---------------------------------------------------------------------------
VULN_PORTS = {
    21:   {"service": "FTP",        "severity": "critical", "threat": "Unencrypted FTP credential theft"},
    22:   {"service": "SSH",        "severity": "low",      "threat": "SSH brute-force attempt"},
    23:   {"service": "Telnet",     "severity": "critical", "threat": "Telnet session hijacking"},
    25:   {"service": "SMTP",       "severity": "medium",   "threat": "SMTP relay abuse"},
    80:   {"service": "HTTP",       "severity": "medium",   "threat": "Unencrypted web traffic interception"},
    443:  {"service": "HTTPS",      "severity": "low",      "threat": "SSL/TLS inspection bypass"},
    445:  {"service": "SMB",        "severity": "high",     "threat": "EternalBlue / ransomware lateral movement"},
    1433: {"service": "MSSQL",      "severity": "high",     "threat": "Database credential brute-force"},
    3306: {"service": "MySQL",      "severity": "high",     "threat": "Database exfiltration attempt"},
    3389: {"service": "RDP",        "severity": "high",     "threat": "RDP brute-force / BlueKeep exploit"},
    5432: {"service": "PostgreSQL", "severity": "high",     "threat": "Database privilege escalation"},
    8080: {"service": "HTTP-Alt",   "severity": "medium",   "threat": "Management interface enumeration"},
}

# Zone → realistic IP subnet mapping
ZONE_SUBNETS = {
    "internet_edge": "203.0.113",
    "untrust":        "198.51.100",
    "outside":        "203.0.113",
    "wan":            "203.0.113",
    "dmz":            "172.16.10",
    "trust":          "10.10.10",
    "internal":       "10.10.10",
    "inside":         "10.10.10",
    "app_servers":    "10.20.0",
    "application":    "10.20.0",
    "database_servers": "10.30.0",
    "database":       "10.30.0",
    "branch_network": "10.40.0",
    "branch":         "10.40.0",
    "management":     "192.168.100",
    "mgmt":           "192.168.100",
    "vpn":            "10.50.0",
    "core":           "10.60.0",
}

def _ip_for_zone(zone: str, host: int = None) -> str:
    subnet = ZONE_SUBNETS.get(zone.lower(), "10.0.0")
    h = host if host is not None else random.randint(2, 254)
    return f"{subnet}.{h}"

def _port_to_int(port_str: str) -> int | None:
    try:
        return int(port_str)
    except Exception:
        return None

def _ts(offset_minutes: int = 0) -> str:
    t = datetime.datetime(2026, 3, 17, 14, 0, 0) - datetime.timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%d %H:%M:%S")


class BaseConfigParser:
    def parse_rules(self, content: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def parse_topology(self, content: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared: derive synthetic connections + threats from parsed rules
    # ------------------------------------------------------------------
    def derive_synthetic_data(
        self,
        rules: List[Dict[str, Any]],
        topology: List[Dict[str, Any]],
        device_name: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Given parsed rules and topology, generate realistic synthetic:
          - connections  (one per rule, representing normal traffic)
          - threats      (one per risky allow rule)
        No mock data — everything derives from the actual config content.
        """
        connections = []
        threats = []
        zones = [t.get("zone", "unknown") for t in topology]

        for i, rule in enumerate(rules):
            src_zone = rule.get("source_ip", "any")
            dst_zone = rule.get("dest_ip", "any")
            port_str = rule.get("dest_port", "any")
            action = rule.get("action", "deny").lower()
            rule_name = rule.get("rule_name", f"rule-{i}")

            # Map zone names to IPs
            src_ip = _ip_for_zone(src_zone if src_zone != "any" else (zones[0] if zones else "trust"), i + 2)
            dst_ip = _ip_for_zone(dst_zone if dst_zone != "any" else (zones[-1] if zones else "dmz"), 10 + i)

            port = _port_to_int(port_str) or 443
            proto = "tcp" if port not in [53, 161, 500] else "udp"

            # Build connection record
            offset = i * 3
            conn = {
                "timestamp": _ts(offset),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 50000 + (i * 317 % 15000),
                "dst_port": port,
                "protocol": proto,
                "action": "allow" if action == "allow" else "deny",
                "rule_id": rule_name,
                "bytes_sent": (i + 1) * 4096,
                "bytes_received": (i + 1) * 16384,
                "packets_sent": (i + 1) * 8,
                "packets_received": (i + 1) * 32,
                "app_name": VULN_PORTS.get(port, {}).get("service", "unknown"),
                "app_category": "network",
                "domain": f"{dst_zone.replace('_', '-')}.internal" if dst_zone != "any" else "external.net",
                "device_name": device_name,
                "zone_from": src_zone if src_zone != "any" else "trust",
                "zone_to": dst_zone if dst_zone != "any" else "dmz",
                "geo_src_country": "US",
                "geo_dst_country": "US",
                "session_end": _ts(offset - 1),
                "duration_seconds": 30 + i * 5,
                "interface_in": "eth0",
                "interface_out": "eth1",
                "threat_detected": port in VULN_PORTS and action == "allow",
            }
            connections.append(conn)

            # Generate threat if this is a risky allow rule
            if action == "allow" and port in VULN_PORTS:
                meta = VULN_PORTS[port]
                threat = {
                    "timestamp": _ts(offset),
                    "device_name": device_name,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "threat_type": "policy_violation",
                    "threat_name": f"{meta['threat']} via {rule_name}",
                    "severity": meta["severity"],
                    "risk_score": {"critical": 9, "high": 7, "medium": 5, "low": 2}[meta["severity"]],
                    "file_name": None,
                    "file_hash": None,
                    "file_size": None,
                    "file_type": None,
                }
                threats.append(threat)

        return {"connections": connections, "threats": threats}


class PaloAltoXMLParser(BaseConfigParser):
    def parse_rules(self, content: str) -> List[Dict[str, Any]]:
        rules = []
        try:
            root = ET.fromstring(content)
            rule_elements = root.findall(".//rulebase/security/rules/entry")
            for i, entry in enumerate(rule_elements):
                rule = {
                    "rule_name":     entry.get("name"),
                    "rule_position": i + 1,
                    "source_ip":     self._get_text(entry, "from/member", "any"),
                    "source_port":   "any",
                    "dest_ip":       self._get_text(entry, "to/member", "any"),
                    "dest_port":     self._get_text(entry, "service/member", "any"),
                    "protocol":      "any",
                    "action":        self._get_text(entry, "action", "deny"),
                    "service_name":  self._get_text(entry, "service/member", "any"),
                    "is_enabled":    entry.find("disabled") is None or self._get_text(entry, "disabled", "no") == "no",
                }
                rules.append(rule)
        except Exception as e:
            logger.error(f"Error parsing Palo Alto XML rules: {e}")
        return rules

    def parse_topology(self, content: str) -> List[Dict[str, Any]]:
        devices = []
        try:
            root = ET.fromstring(content)
            # Try multiple XPaths: singular "zone" (PAN-OS running config)
            # and plural "zones" (ComplyGuard / exported config format)
            zones = root.findall(".//vsys/entry/zone/entry")
            if not zones:
                zones = root.findall(".//zones/entry")
            if not zones:
                zones = root.findall(".//zone/entry")
            for zone in zones:
                name = zone.get("name", "")
                is_entry = zone.findtext("is-entry-point", "no").lower() == "yes"
                if not is_entry:
                    is_entry = "untrust" in name.lower() or "internet" in name.lower() or "outside" in name.lower() or "wan" in name.lower()
                interfaces = []
                net = zone.find("network")
                if net is not None:
                    layer3 = net.find("layer3")
                    if layer3 is not None:
                        interfaces = [m.text for m in layer3 if m.text]
                devices.append({
                    "device_type":    "firewall",
                    "zone":           name,
                    "ip_address":     _ip_for_zone(name, 1),
                    "ports_open":     [],
                    "is_entry_point": is_entry,
                    "interfaces":     interfaces,
                    "trust_level":    zone.findtext("trust-level", ""),
                    "description":    zone.findtext("description", ""),
                })
        except Exception as e:
            logger.error(f"Error parsing Palo Alto XML topology: {e}")
        return devices

    def _get_text(self, element, path, default=None):
        found = element.find(path)
        return found.text if found is not None and found.text else default


class CiscoASAParser(BaseConfigParser):
    def parse_rules(self, content: str) -> List[Dict[str, Any]]:
        rules = []
        pattern = re.compile(
            r'access-list\s+(\S+)\s+extended\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+eq\s+(\d+)'
        )
        for i, line in enumerate(content.splitlines()):
            m = pattern.search(line)
            if m:
                g = m.groups()
                rules.append({
                    "rule_name":     g[0],
                    "rule_position": i + 1,
                    "action":        g[1],
                    "protocol":      g[2],
                    "source_ip":     g[3] if g[3] != "host" else g[4],
                    "source_port":   "any",
                    "dest_ip":       g[5] if g[5] != "host" else g[6],
                    "dest_port":     g[7] if g[5] != "host" else g[7],
                    "is_enabled":    True,
                })
        return rules

    def parse_topology(self, content: str) -> List[Dict[str, Any]]:
        devices = []
        pattern = re.compile(r'nameif\s+(\S+)')
        for line in content.splitlines():
            m = pattern.search(line)
            if m:
                name = m.group(1)
                devices.append({
                    "device_type":    "firewall",
                    "zone":           name,
                    "ip_address":     _ip_for_zone(name, 1),
                    "ports_open":     [],
                    "is_entry_point": "outside" in name.lower(),
                })
        return devices


class FortinetParser(BaseConfigParser):
    def parse_rules(self, content: str) -> List[Dict[str, Any]]:
        rules = []
        policy_blocks = re.findall(r'edit (\d+)\n(.*?)\n\s+next', content, re.DOTALL)
        for policy_id, block in policy_blocks:
            rules.append({
                "rule_name":     f"Policy {policy_id}",
                "rule_position": int(policy_id),
                "source_ip":     self._extract_value(block, "srcaddr"),
                "dest_ip":       self._extract_value(block, "dstaddr"),
                "source_port":   "any",
                "dest_port":     "any",
                "protocol":      "any",
                "service_name":  self._extract_value(block, "service"),
                "action":        "allow" if "accept" in block else "deny",
                "is_enabled":    "set status disable" not in block,
            })
        return rules

    def parse_topology(self, content: str) -> List[Dict[str, Any]]:
        devices = []
        interface_blocks = re.findall(r'config system interface\n(.*?)\nend', content, re.DOTALL)
        if interface_blocks:
            interfaces = re.findall(r'edit "([^"]+)"', interface_blocks[0])
            for intf in interfaces:
                devices.append({
                    "device_type":    "firewall",
                    "zone":           intf,
                    "ip_address":     _ip_for_zone(intf, 1),
                    "ports_open":     [],
                    "is_entry_point": "wan" in intf.lower() or "internet" in intf.lower(),
                })
        return devices

    def _extract_value(self, block, key):
        m = re.search(f'set {key} "([^"]+)"', block)
        return m.group(1) if m else "any"
