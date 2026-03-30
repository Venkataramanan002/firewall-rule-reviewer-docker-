"""
utils/attack_surface_engine.py
──────────────────────────────
Standalone Attack Surface Analyser.

Evaluates the risk of direct interaction between two IP addresses using:
  · Firewall interaction data from a CSV file
      (columns: source_ip, destination_ip, port, protocol, access_type)
  · Risk weight model from an XML file under <interactionRiskModel>

Public API
──────────
  AttackSurfaceResult
  run_attack_surface_analysis(source_ip, dest_ip, csv_path, xml_path)

  AttackSurfaceResult
  run_attack_surface_analysis_from_data(source_ip, dest_ip, rows, port_weights, modifiers)

Design notes
────────────
  * No assumptions about CVEs — only exposure and interaction risk.
  * Modular: all sub-steps are isolated functions for future CVE integration.
  * Graph representation included: nodes = IPs, edges = allowed communication.
"""
from __future__ import annotations

import csv
import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class PortRiskWeight:
    port: int
    service: str
    base_risk: float


@dataclass
class RuleModifier:
    condition: str   # e.g. "public_access" | "internal_only"
    boost: float


@dataclass
class PortContribution:
    port: str
    protocol: str
    access_type: str
    base_risk: float
    modifier: float
    total: float
    service: str
    explanation: str
    lateral_movement: bool
    attack_vector: str


@dataclass
class SurfaceGraphNode:
    id: str
    ip: str
    is_source: bool = False
    is_target: bool = False


@dataclass
class SurfaceGraphEdge:
    source: str
    target: str
    port: str
    protocol: str
    risk_score: float
    access_type: str


@dataclass
class SurfaceGraph:
    nodes: List[SurfaceGraphNode]
    edges: List[SurfaceGraphEdge]


@dataclass
class AttackSurfaceResult:
    source_ip: str
    destination_ip: str
    allowed_ports: List[PortContribution]
    risk_score: float               # aggregated total
    risk_level: str                 # Low / Medium / High / Critical
    explanation: List[str]          # per-port narrative lines
    lateral_movement_risk: str      # None / Possible / High
    lateral_movement_paths: List[str]
    attack_vectors: List[str]       # specific per-port attack scenarios
    bidirectional_exposure: bool    # true if traffic was found in both directions
    graph: SurfaceGraph
    path_exists: bool


# ── Lateral-movement signatures ───────────────────────────────────────────────

_LATERAL_PORTS: Dict[int, str] = {
    22:    "SSH enables reverse shell pivoting and agent forwarding to downstream hosts",
    23:    "Telnet session hijacking enables full command execution",
    135:   "MSRPC allows remote WMI execution for lateral spread",
    139:   "NetBIOS/SMB relay enables domain-wide credential theft",
    445:   "SMB (EternalBlue) enables ransomware propagation across the subnet",
    3389:  "RDP session allows interactive graphical pivoting to downstream hosts",
    5985:  "WinRM enables PowerShell remoting for lateral movement",
    5986:  "WinRM/HTTPS enables encrypted PowerShell remoting",
    4444:  "Known Metasploit default listener — direct interactive shell access",
    50050: "Cobalt Strike Teamserver port — active adversary C2 infrastructure",
}

# Ports that elevate lateral movement to "High" severity
_LATERAL_HIGH_PORTS: set = {445, 3389, 4444, 50050, 23}

# ── Attack vector signatures (self-contained, no CVE assumptions) ─────────────

_ATTACK_VECTORS: Dict[int, str] = {
    21:    "FTP credential sniffing → arbitrary file upload / download via anonymous login",
    22:    "SSH brute-force or stolen private key → persistent backdoor with agent forwarding",
    23:    "Telnet plain-text sniffing → full credentials captured in a single packet",
    25:    "Open SMTP relay → phishing / spam origination; VRFY mailbox enumeration",
    53:    "DNS zone transfer → full internal hostname map; cache poisoning for MITM",
    80:    "HTTP injection (SQLi / XSS / CSRF) → web application compromise over clear-text channel",
    443:   "TLS downgrade / MITM attack or encrypted C2 traffic blending with normal HTTPS",
    445:   "SMB exploit (EternalBlue) → SYSTEM shell → worm-style lateral spread",
    1433:  "MS-SQL xp_cmdshell → OS command execution as service account",
    1521:  "Oracle TNS poisoning → SID enumeration → default credential (scott/tiger) abuse",
    3306:  "MySQL SELECT INTO OUTFILE → arbitrary web-server write → webshell upload",
    3389:  "RDP BlueKeep / credential stuffing → interactive desktop session → local persistence",
    5432:  "PostgreSQL COPY FROM PROGRAM → OS command execution; arbitrary file read",
    6379:  "Redis unauthenticated → config rewrite → SSH authorised-key injection",
    9200:  "Elasticsearch unauthenticated API → full index dump and cluster takeover",
    27017: "MongoDB unauthenticated → full collection dump and admin command execution",
    2375:  "Unencrypted Docker API → container escape → host root shell",
    6443:  "Kubernetes API server → RBAC misconfiguration → cluster-admin escalation",
    502:   "Modbus / ICS command injection → physical process manipulation (OT impact)",
    4444:  "Active Metasploit handler → immediate interactive shell session",
    50050: "Cobalt Strike Teamserver → active APT C2 channel with full post-exploitation",
}


# ── Risk level thresholds ─────────────────────────────────────────────────────

def _risk_level(score: float) -> str:
    """Map aggregated numeric score to a human-readable tier."""
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


# ── XML parser ────────────────────────────────────────────────────────────────

def parse_risk_model(
    xml_path: str,
) -> Tuple[Dict[int, PortRiskWeight], List[RuleModifier]]:
    """
    Parses <interactionRiskModel> from the XML config file.
    Returns (port_weights_by_port_number, rule_modifiers).
    Falls back to sensible defaults when the section is absent or the file
    cannot be read — allowing the engine to run standalone.
    """
    port_weights: Dict[int, PortRiskWeight] = {}
    modifiers: List[RuleModifier] = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        model = root.find(".//interactionRiskModel")
        if model is None:
            return _default_weights(), _default_modifiers()

        for port_el in model.findall(".//riskWeights/port"):
            try:
                num     = int(port_el.get("number", "0"))
                service = port_el.get("service", f"Port-{num}")
                risk    = float(port_el.get("risk", "1"))
                port_weights[num] = PortRiskWeight(port=num, service=service, base_risk=risk)
            except (ValueError, TypeError):
                continue

        for rule_el in model.findall(".//rules/rule"):
            cond_el  = rule_el.find("condition")
            boost_el = rule_el.find("riskBoost")
            if cond_el is not None and boost_el is not None:
                try:
                    modifiers.append(
                        RuleModifier(
                            condition=cond_el.text.strip(),
                            boost=float(boost_el.text.strip()),
                        )
                    )
                except (ValueError, AttributeError):
                    continue

    except (ET.ParseError, FileNotFoundError, OSError):
        pass

    if not port_weights:
        port_weights = _default_weights()
    if not modifiers:
        modifiers = _default_modifiers()

    return port_weights, modifiers


def _default_weights() -> Dict[int, PortRiskWeight]:
    return {
        22:   PortRiskWeight(22,   "SSH",   3.0),
        80:   PortRiskWeight(80,   "HTTP",  2.0),
        443:  PortRiskWeight(443,  "HTTPS", 2.0),
        3306: PortRiskWeight(3306, "MySQL", 8.0),
        3389: PortRiskWeight(3389, "RDP",   7.0),
    }


def _default_modifiers() -> List[RuleModifier]:
    return [
        RuleModifier("public_access", 5.0),
        RuleModifier("internal_only", 1.0),
    ]


# ── CSV parser ────────────────────────────────────────────────────────────────

def parse_csv_interactions(csv_path: str) -> List[Dict[str, str]]:
    """
    Reads the CSV with columns:
      source_ip, destination_ip, port, protocol, access_type
    Returns a list of row dicts (all values normalised to stripped strings).
    """
    rows: List[Dict[str, str]] = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for raw_row in reader:
                rows.append(
                    {k.strip(): (v or "").strip() for k, v in raw_row.items()}
                )
    except (FileNotFoundError, OSError):
        pass
    return rows


# ── IP matching ───────────────────────────────────────────────────────────────

def _ip_matches(ip: str, rule_field: str) -> bool:
    """Return True when `ip` is covered by `rule_field` (any / CIDR / exact)."""
    rule_field = rule_field.strip()
    if rule_field in {"any", "all", "*", "0.0.0.0/0", "0.0.0.0"}:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if "/" in rule_field:
            return addr in ipaddress.ip_network(rule_field, strict=False)
        return addr == ipaddress.ip_address(rule_field)
    except ValueError:
        return False


# ── Modifier lookup ───────────────────────────────────────────────────────────

def _get_modifier(access_type: str, modifiers: List[RuleModifier]) -> float:
    """
    Match access_type string against rule conditions (fuzzy, strip separators).
    Returns the boost value for the first match, or 1.0 if nothing matches.
    """
    normalised = access_type.lower().replace("_", "").replace("-", "")
    for mod in modifiers:
        cond = mod.condition.lower().replace("_", "").replace("-", "")
        if cond in normalised or normalised in cond:
            return mod.boost
    return 1.0


# ── Port number extraction ────────────────────────────────────────────────────

def _extract_port_number(port_str: str) -> int:
    """Best-effort extraction of a primary port number from a port string."""
    try:
        clean = re.sub(r"[^0-9]", "", port_str.split(",")[0].split("-")[0])
        return int(clean) if clean else 0
    except (ValueError, IndexError):
        return 0


# ── Public entry points ───────────────────────────────────────────────────────

def run_attack_surface_analysis(
    source_ip: str,
    dest_ip: str,
    csv_path: str,
    xml_path: str,
) -> AttackSurfaceResult:
    """
    Load CSV + XML from disk and run the full attack surface analysis.
    Safe to call as a standalone script.
    """
    rows = parse_csv_interactions(csv_path)
    port_weights, modifiers = parse_risk_model(xml_path)
    return _analyse(source_ip, dest_ip, rows, port_weights, modifiers)


def run_attack_surface_analysis_from_data(
    source_ip: str,
    dest_ip: str,
    rows: List[Dict[str, str]],
    port_weights: Dict[int, PortRiskWeight],
    modifiers: List[RuleModifier],
) -> AttackSurfaceResult:
    """
    Entry point when the caller has already parsed CSV / XML (e.g. cached).
    """
    return _analyse(source_ip, dest_ip, rows, port_weights, modifiers)


# ── Core analysis logic ───────────────────────────────────────────────────────

def _analyse(
    source_ip: str,
    dest_ip: str,
    rows: List[Dict[str, str]],
    port_weights: Dict[int, PortRiskWeight],
    modifiers: List[RuleModifier],
) -> AttackSurfaceResult:
    """
    Main analysis pipeline:
      1. Filter CSV rows that match the requested IP pair (forward + reverse).
      2. Deduplicate by (port, protocol).
      3. Assign base risk from XML port weights; apply access_type modifier.
      4. Classify lateral movement risk.
      5. Collect attack vectors.
      6. Build graph.
    """

    # ── 1. Match rows ─────────────────────────────────────────────────────────
    forward_matches: List[Dict[str, str]] = []
    reverse_matches: List[Dict[str, str]] = []

    for row in rows:
        src_field = row.get("source_ip", "")
        dst_field = row.get("destination_ip", "")
        if _ip_matches(source_ip, src_field) and _ip_matches(dest_ip, dst_field):
            forward_matches.append({**row, "_direction": "forward"})
        elif _ip_matches(dest_ip, src_field) and _ip_matches(source_ip, dst_field):
            reverse_matches.append({**row, "_direction": "reverse"})

    all_matches = forward_matches + reverse_matches
    bidirectional = len(forward_matches) > 0 and len(reverse_matches) > 0
    path_exists   = len(all_matches) > 0

    # ── 2. Deduplicate by (port, protocol) ────────────────────────────────────
    seen_key: set = set()
    contributions: List[PortContribution] = []
    total_risk = 0.0
    lateral_ports: List[str] = []
    attack_vectors: List[str] = []

    for row in all_matches:
        port_str    = row.get("port", "any")
        protocol    = row.get("protocol", "TCP").upper()
        access_type = row.get("access_type", "unknown")
        key = (port_str, protocol)
        if key in seen_key:
            continue
        seen_key.add(key)

        port_num = _extract_port_number(port_str)
        weight   = port_weights.get(port_num)
        base_risk = weight.base_risk if weight else 5.0
        service   = weight.service   if weight else f"Port-{port_str}"

        modifier           = _get_modifier(access_type, modifiers)
        total_contribution = base_risk + modifier
        total_risk        += total_contribution

        # Per-port explanation
        access_label = (
            "the public internet" if "public" in access_type.lower()
            else "the internal network"
        )
        direction_note = (
            " (bidirectional exposure detected)"
            if bidirectional and row.get("_direction") == "reverse"
            else ""
        )
        explanation = (
            f"Port {port_str} ({service}) is accessible from {access_label}{direction_note}. "
            f"Base risk weight: {base_risk:.1f} + access modifier: +{modifier:.1f} "
            f"= contribution {total_contribution:.1f}."
        )

        # Lateral movement
        is_lateral = port_num in _LATERAL_PORTS
        if is_lateral:
            lateral_desc = (
                f"Port {port_str} ({service}): {_LATERAL_PORTS[port_num]}"
            )
            if lateral_desc not in lateral_ports:
                lateral_ports.append(lateral_desc)

        # Attack vector
        av = _ATTACK_VECTORS.get(port_num)
        if av:
            entry = f"Port {port_str}: {av}"
            if entry not in attack_vectors:
                attack_vectors.append(entry)

        contributions.append(
            PortContribution(
                port=port_str,
                protocol=protocol,
                access_type=access_type,
                base_risk=base_risk,
                modifier=modifier,
                total=round(total_contribution, 1),
                service=service,
                explanation=explanation,
                lateral_movement=is_lateral,
                attack_vector=av or "",
            )
        )

    # ── 3. Lateral movement classification ────────────────────────────────────
    high_lateral = any(
        _extract_port_number(c.port) in _LATERAL_HIGH_PORTS
        for c in contributions
        if c.lateral_movement
    )
    if high_lateral and lateral_ports:
        lateral_movement_risk = "High"
    elif lateral_ports:
        lateral_movement_risk = "Possible"
    else:
        lateral_movement_risk = "None"

    # ── 4. Explanation lines ──────────────────────────────────────────────────
    explanation_lines = [c.explanation for c in contributions]

    if bidirectional:
        explanation_lines.append(
            "Bidirectional exposure detected: traffic is permitted in both directions "
            "between these IPs, significantly widening the attack surface."
        )

    if lateral_ports:
        explanation_lines.append(
            f"Lateral movement risk is {lateral_movement_risk.upper()} — "
            "the following connections can be used to pivot to downstream hosts: "
            + "; ".join(lateral_ports)
        )

    # ── 5. Build graph ────────────────────────────────────────────────────────
    src_id = "n_" + re.sub(r"[^a-zA-Z0-9]", "_", source_ip)
    dst_id = "n_" + re.sub(r"[^a-zA-Z0-9]", "_", dest_ip)

    graph = SurfaceGraph(
        nodes=[
            SurfaceGraphNode(id=src_id, ip=source_ip, is_source=True),
            SurfaceGraphNode(id=dst_id, ip=dest_ip,   is_target=True),
        ],
        edges=[
            SurfaceGraphEdge(
                source=src_id,
                target=dst_id,
                port=c.port,
                protocol=c.protocol,
                risk_score=c.total,
                access_type=c.access_type,
            )
            for c in contributions
        ],
    )

    return AttackSurfaceResult(
        source_ip=source_ip,
        destination_ip=dest_ip,
        allowed_ports=contributions,
        risk_score=round(total_risk, 1),
        risk_level=_risk_level(total_risk),
        explanation=explanation_lines,
        lateral_movement_risk=lateral_movement_risk,
        lateral_movement_paths=lateral_ports,
        attack_vectors=attack_vectors,
        bidirectional_exposure=bidirectional,
        graph=graph,
        path_exists=path_exists,
    )


# ── CLI usage ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 5:
        print(
            "Usage: python attack_surface_engine.py "
            "<source_ip> <dest_ip> <csv_path> <xml_path>"
        )
        sys.exit(1)

    result = run_attack_surface_analysis(
        sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    )

    output = {
        "source_ip":             result.source_ip,
        "destination_ip":        result.destination_ip,
        "risk_score":            result.risk_score,
        "risk_level":            result.risk_level,
        "path_exists":           result.path_exists,
        "bidirectional":         result.bidirectional_exposure,
        "lateral_movement_risk": result.lateral_movement_risk,
        "allowed_ports": [
            {
                "port":         p.port,
                "service":      p.service,
                "protocol":     p.protocol,
                "access_type":  p.access_type,
                "base_risk":    p.base_risk,
                "modifier":     p.modifier,
                "total":        p.total,
                "lateral":      p.lateral_movement,
            }
            for p in result.allowed_ports
        ],
        "explanation":     result.explanation,
        "attack_vectors":  result.attack_vectors,
    }
    print(json.dumps(output, indent=2))
