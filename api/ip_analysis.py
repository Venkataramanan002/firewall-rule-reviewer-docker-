"""
api/ip_analysis.py
──────────────────
IP-to-IP vulnerability analysis.

Endpoints:
  GET  /api/topology/ips      Returns every IP known to the system (topology,
                              rules, recent connections).  Used to populate the
                              two IP comboboxes in the frontend.

  POST /api/ip-vulnerability  Given two IPs, finds all firewall rules that
                              allow traffic between them, builds a mini graph,
                              enriches each connection with exploit methods and
                              remediations, and returns the result.

  POST /api/attack-surface    CSV + XML driven attack surface analysis between
                              two IPs.  Parses risk weights from the firewall
                              XML config and interaction data from the CSV, then
                              returns a scored breakdown with lateral movement
                              classification and per-port attack vectors.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import Connection, FirewallRule, NetworkTopology, RuleRiskAnalysis
from utils.attack_surface_engine import (
    run_attack_surface_analysis,
    parse_risk_model,
    parse_csv_interactions,
    AttackSurfaceResult,
)

# Resolve default data-file paths relative to the project root
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CSV_PATH = os.path.join(_PROJECT_ROOT, "complyguard_interactions.csv")
_DEFAULT_XML_PATH = os.path.join(_PROJECT_ROOT, "complyguard_ultra_complete.xml")

router = APIRouter(prefix="/api", tags=["IP Analysis"])
logger = logging.getLogger(__name__)

# ── Port info dictionary ────────────────────────────────────────────────────

_PORT_INFO: Dict[int, Dict[str, Any]] = {
    21:   {"service": "FTP",        "risk": 8.0,
           "method": "Unencrypted FTP credentials captured by passive sniffing; anonymous login abuse",
           "fixes": ["Replace FTP with SFTP (port 22)", "Block from public internet", "Require certificate-based auth"]},
    22:   {"service": "SSH",        "risk": 4.5,
           "method": "SSH brute-force or stolen private key; lateral movement if password authentication is enabled",
           "fixes": ["Disable password auth; require SSH keys only", "Restrict source IPs to a bastion host", "Enable fail2ban / rate-limiting"]},
    23:   {"service": "Telnet",     "risk": 9.5,
           "method": "All Telnet traffic is plaintext; credentials captured with passive sniffing",
           "fixes": ["Disable Telnet immediately and replace with SSH", "Block at perimeter firewall"]},
    25:   {"service": "SMTP",       "risk": 5.5,
           "method": "Open relay abuse for spam and phishing; VRFY command exposed for mailbox enumeration",
           "fixes": ["Restrict relay to authorised mail servers only", "Enable SPF / DKIM / DMARC", "Disable VRFY and EXPN commands"]},
    53:   {"service": "DNS",        "risk": 5.5,
           "method": "DNS amplification DDoS, zone transfer to enumerate all hostnames, cache poisoning",
           "fixes": ["Restrict zone transfers to authorised secondaries", "Enable DNSSEC", "Rate-limit queries from untrusted sources"]},
    80:   {"service": "HTTP",       "risk": 6.5,
           "method": "SQL injection, XSS, CSRF over unencrypted channel; credentials visible in transit",
           "fixes": ["Redirect all traffic to HTTPS (443)", "Deploy WAF with OWASP Top 10 rules", "Enable HSTS headers"]},
    110:  {"service": "POP3",       "risk": 6.0,
           "method": "Unencrypted email credentials captured on the wire; full mailbox access once credential stolen",
           "fixes": ["Force POP3S (port 995)", "Migrate to IMAP over TLS", "Restrict to internal mail clients only"]},
    135:  {"service": "MSRPC",      "risk": 6.5,
           "method": "Windows RPC endpoint enumeration; DCOM exploitation; MS03-026 and similar RPC exploits",
           "fixes": ["Block at perimeter firewall", "Apply all Windows RPC security patches", "Disable unneeded DCOM services"]},
    139:  {"service": "NetBIOS",    "risk": 7.0,
           "method": "NetBIOS name enumeration; NBNS spoofing; credential harvesting via Responder tool",
           "fixes": ["Block at perimeter firewall", "Disable NetBIOS over TCP/IP if SMB is not required", "Segment internal networks"]},
    143:  {"service": "IMAP",       "risk": 6.0,
           "method": "Unencrypted email access; credential capture; full mailbox enumeration",
           "fixes": ["Force IMAPS (port 993)", "Restrict to internal mail clients only"]},
    443:  {"service": "HTTPS",      "risk": 3.0,
           "method": "TLS weakness exploitation (downgrade attacks); certificate spoofing; encrypted-channel abuse for C2",
           "fixes": ["Enforce TLS 1.2+; disable TLS 1.0/1.1 and SSLv3", "Enable certificate pinning", "Deploy SSL inspection for outbound"]},
    445:  {"service": "SMB",        "risk": 9.5,
           "method": "EternalBlue / WannaCry exploit (MS17-010); Pass-the-Hash credential relay; ransomware propagation across subnets",
           "fixes": ["Block SMB from internet immediately", "Apply MS17-010 patch on all Windows hosts", "Disable SMBv1; enforce SMB signing"]},
    1433: {"service": "MS-SQL",     "risk": 8.5,
           "method": "SA account brute-force; xp_cmdshell for remote code execution; database enumeration and exfiltration",
           "fixes": ["Restrict SQL to the application server only", "Disable sa account; use least-privilege accounts", "Enable SQL Server audit logging"]},
    1521: {"service": "Oracle",     "risk": 8.5,
           "method": "TNS Listener poisoning; SID enumeration; default credential abuse (scott/tiger)",
           "fixes": ["Restrict access to application server IP only", "Remove default accounts", "Enable Oracle Unified Auditing"]},
    3306: {"service": "MySQL",      "risk": 8.0,
           "method": "Credential brute-force; SELECT INTO OUTFILE for arbitrary file write; UDF injection for RCE",
           "fixes": ["Bind MySQL to localhost if remote access not required", "Remove anonymous users and test databases", "Enable binary logging"]},
    3389: {"service": "RDP",        "risk": 9.0,
           "method": "BlueKeep / DejaBlue exploit; credential stuffing; ransomware entry and lateral movement using RDP sessions",
           "fixes": ["Move RDP behind VPN; remove direct internet exposure", "Enable Network Level Authentication (NLA)", "Apply CVE-2019-0708 (BlueKeep) patch"]},
    5432: {"service": "PostgreSQL", "risk": 8.0,
           "method": "pg_read_file / COPY TO for arbitrary file read; COPY FROM PROGRAM for RCE; credential brute-force",
           "fixes": ["Restrict pg_hba.conf to application server IPs", "Disable COPY TO/FROM PROGRAM", "Enable SSL for all connections"]},
    8080: {"service": "HTTP-Alt",   "risk": 6.5,
           "method": "Same attack surface as HTTP port 80; development / admin panels often exposed without auth",
           "fixes": ["Redirect to HTTPS", "Restrict to internal IPs only", "Disable debug endpoints"]},
    8443: {"service": "HTTPS-Alt",  "risk": 3.5,
           "method": "Non-production HTTPS; often weaker TLS configurations; admin panels exposed",
           "fixes": ["Enforce same TLS policy as port 443", "Restrict to authorised source IPs"]},
}

_GENERIC_FIXES = [
    "Restrict source IP range to the minimum required set",
    "Enable connection logging for this rule",
    "Review quarterly whether the rule is still needed",
]


def _port_details(port_str: str) -> Tuple[float, str, List[str]]:
    """Return (risk_score, compromise_method, remediations) for a port string."""
    try:
        clean = re.sub(r"[^0-9]", "", port_str.split(",")[0].split("-")[0])
        port = int(clean) if clean else 0
    except (ValueError, AttributeError):
        port = 0

    info = _PORT_INFO.get(port)
    if info:
        return info["risk"], info["method"], info["fixes"]

    return 5.0, (
        f"Unknown service on port {port_str}. "
        "An attacker can probe the port with nmap -sV to identify the service and search for known vulnerabilities."
    ), _GENERIC_FIXES


def _risk_str(score: float) -> str:
    if score >= 8: return "critical"
    if score >= 6: return "high"
    if score >= 4: return "medium"
    return "low"


def _ip_in_rule(ip: str, rule_ip_field: str) -> bool:
    """Return True when `ip` is covered by a rule's source/dest field."""
    if not ip or not rule_ip_field:
        return False
    raw = rule_ip_field.strip().lower()
    if raw in {"any", "all", "*", "0.0.0.0/0", "0.0.0.0"}:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for token in re.split(r"[,\s]+", rule_ip_field):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                if addr in ipaddress.ip_network(token, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(token):
                    return True
    except ValueError:
        pass
    return False


def _topo_for_ip(ip: str, nodes: List[NetworkTopology]) -> Optional[NetworkTopology]:
    for n in nodes:
        if n.ip_address and n.ip_address.strip() == ip.strip():
            return n
    return None


def _label(ip: str, nodes: List[NetworkTopology]) -> str:
    n = _topo_for_ip(ip, nodes)
    if n and n.device_name and n.device_name != ip:
        return f"{n.device_name}"
    return ip


# ── Models ─────────────────────────────────────────────────────────────────

class IPEntry(BaseModel):
    ip: str
    label: str
    zone: Optional[str] = None
    device_type: Optional[str] = None
    is_firewall: bool = False


class IPListResponse(BaseModel):
    ips: List[IPEntry]
    total: int


class IPVulnerabilityRequest(BaseModel):
    source_ip: str
    target_ip: str


class VulnNode(BaseModel):
    id: str
    ip: str
    label: str
    zone: Optional[str] = None
    device_type: Optional[str] = None
    is_firewall: bool = False
    is_source: bool = False
    is_target: bool = False


class VulnEdge(BaseModel):
    id: str
    source_node: str        # node id
    target_node: str        # node id
    rule_name: str
    port: str
    protocol: str
    risk_score: float
    risk_level: str
    compromise_method: str
    compromisability: float  # 0–10
    remediations: List[str]


class IPVulnerabilityResponse(BaseModel):
    source: Optional[IPEntry] = None
    target: Optional[IPEntry] = None
    nodes: List[VulnNode]
    edges: List[VulnEdge]
    overall_risk: float
    risk_level: str
    path_exists: bool
    hop_count: int
    summary: str
    source_found: bool
    target_found: bool


# ── Endpoint 1: list all IPs known to the firewall system ─────────────────

@router.get("/topology/ips", response_model=IPListResponse)
async def list_firewall_ips(db: AsyncSession = Depends(get_db)) -> IPListResponse:
    """
    Returns every IP address the system has data about:
      · NetworkTopology nodes (most authoritative)
      · Specific (non-wildcard ≥ /24) source/dest IPs from FirewallRule
      · Unique src/dst IPs from the last 5 000 Connection rows

    Used to populate the IP-to-IP vulnerability selector dropdowns.
    """
    seen: Set[str] = set()
    entries: List[IPEntry] = []

    # 1. Topology nodes
    topo_result = await db.execute(select(NetworkTopology))
    topo_nodes: List[NetworkTopology] = topo_result.scalars().all()

    for node in topo_nodes:
        ip = (node.ip_address or "").strip()
        if ip and ip not in seen:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            seen.add(ip)
            entries.append(IPEntry(
                ip=ip,
                label=node.device_name or ip,
                zone=node.zone,
                device_type=node.device_type,
                is_firewall=(node.device_type or "").lower() == "firewall",
            ))

    # 2. Rule IPs (specific, non-wildcard, /24 or more specific)
    rules_result = await db.execute(
        select(FirewallRule.source_ip, FirewallRule.dest_ip).distinct()
    )
    for row in rules_result.all():
        for raw in [row.source_ip or "", row.dest_ip or ""]:
            for token in re.split(r"[,\s]+", raw):
                token = token.strip()
                if not token or token.lower() in {"any", "all", "*", "0.0.0.0/0"}:
                    continue
                try:
                    if "/" in token:
                        net = ipaddress.ip_network(token, strict=False)
                        if net.prefixlen < 24:
                            continue
                        ip = str(net.network_address)
                    else:
                        ipaddress.ip_address(token)
                        ip = token
                except ValueError:
                    continue
                if ip not in seen:
                    seen.add(ip)
                    topo = _topo_for_ip(ip, topo_nodes)
                    entries.append(IPEntry(
                        ip=ip,
                        label=topo.device_name if topo else ip,
                        zone=topo.zone if topo else None,
                        device_type=topo.device_type if topo else None,
                        is_firewall=(topo.device_type or "").lower() == "firewall" if topo else False,
                    ))

    # 3. Recent connection IPs (capped)
    conn_result = await db.execute(
        select(Connection.src_ip, Connection.dst_ip)
        .order_by(Connection.timestamp.desc())
        .limit(5000)
    )
    for row in conn_result.all():
        for ip in [row.src_ip or "", row.dst_ip or ""]:
            ip = ip.strip()
            if not ip or ip in seen:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            seen.add(ip)
            topo = _topo_for_ip(ip, topo_nodes)
            entries.append(IPEntry(
                ip=ip,
                label=topo.device_name if topo else ip,
                zone=topo.zone if topo else None,
                device_type=topo.device_type if topo else None,
                is_firewall=False,
            ))

    # Sort: topology-labelled first, then by IP
    entries.sort(key=lambda e: (0 if e.label != e.ip else 1, e.ip))

    return IPListResponse(ips=entries, total=len(entries))


# ── Endpoint 2: IP-to-IP vulnerability analysis ────────────────────────────

@router.post("/ip-vulnerability", response_model=IPVulnerabilityResponse)
async def analyze_ip_vulnerability(
    req: IPVulnerabilityRequest,
    db: AsyncSession = Depends(get_db),
) -> IPVulnerabilityResponse:
    """
    Find all firewall rules that permit traffic between two IPs and return
    a vulnerability graph with per-connection exploit methods and remediations.
    """
    source_ip = req.source_ip.strip()
    target_ip = req.target_ip.strip()

    # ── Load data ──────────────────────────────────────────────────────────
    topo_result = await db.execute(select(NetworkTopology))
    topo_nodes: List[NetworkTopology] = topo_result.scalars().all()

    rules_result = await db.execute(
        select(FirewallRule).where(FirewallRule.is_enabled == True)
    )
    all_rules: List[FirewallRule] = rules_result.scalars().all()

    risk_result = await db.execute(select(RuleRiskAnalysis))
    risk_map: Dict[str, float] = {
        str(r.rule_id): float(r.risk_score) for r in risk_result.scalars().all()
    }

    # ── Validate: are these IPs known to the system? ───────────────────────
    all_known: Set[str] = set()
    for n in topo_nodes:
        if n.ip_address:
            all_known.add(n.ip_address.strip())
    for rule in all_rules:
        for field in [rule.source_ip or "", rule.dest_ip or ""]:
            for token in re.split(r"[,\s]+", field):
                token = token.strip()
                try:
                    ipaddress.ip_address(token)
                    all_known.add(token)
                except ValueError:
                    pass

    source_found = source_ip in all_known or any(_ip_in_rule(source_ip, k) for k in all_known)
    target_found = target_ip in all_known or any(_ip_in_rule(target_ip, k) for k in all_known)

    # ── Find matching rules ─────────────────────────────────────────────────
    # A rule "matches" if:
    #   - forward path: source_ip is covered by rule.source_ip AND target_ip covered by rule.dest_ip
    #   - reverse path: target_ip covered by rule.source_ip AND source_ip covered by rule.dest_ip

    matching_rules: List[Tuple[FirewallRule, bool]] = []  # (rule, is_forward)
    seen_rule_ids: Set[str] = set()

    for rule in all_rules:
        if rule.action.lower() not in {"allow", "permit", "accept"}:
            continue
        rid = str(rule.id)
        if rid in seen_rule_ids:
            continue

        fwd = _ip_in_rule(source_ip, rule.source_ip or "") and _ip_in_rule(target_ip, rule.dest_ip or "")
        rev = _ip_in_rule(target_ip, rule.source_ip or "") and _ip_in_rule(source_ip, rule.dest_ip or "")

        if fwd or rev:
            matching_rules.append((rule, fwd))
            seen_rule_ids.add(rid)

    # ── Build node set ──────────────────────────────────────────────────────
    def _node_id(ip: str) -> str:
        return "n_" + re.sub(r"[^a-zA-Z0-9]", "_", ip)

    def _make_vuln_node(ip: str, is_src: bool = False, is_tgt: bool = False) -> VulnNode:
        topo = _topo_for_ip(ip, topo_nodes)
        return VulnNode(
            id=_node_id(ip),
            ip=ip,
            label=topo.device_name if topo and topo.device_name else ip,
            zone=topo.zone if topo else None,
            device_type=topo.device_type if topo else None,
            is_firewall=(topo.device_type or "").lower() == "firewall" if topo else False,
            is_source=is_src,
            is_target=is_tgt,
        )

    all_node_ips: Set[str] = {source_ip, target_ip}

    # Include any firewall nodes that sit between the two IPs
    firewall_nodes = [n for n in topo_nodes if (n.device_type or "").lower() == "firewall" and n.ip_address]
    for fw in firewall_nodes:
        fw_ip = fw.ip_address.strip()
        # Include firewall if it's mentioned in any matching rule's source or dest
        for rule, _ in matching_rules:
            if (_ip_in_rule(fw_ip, rule.source_ip or "") or _ip_in_rule(fw_ip, rule.dest_ip or "")):
                all_node_ips.add(fw_ip)
                break

    # Build node list: source first, firewalls in middle, target last
    src_node = _make_vuln_node(source_ip, is_src=True)
    tgt_node = _make_vuln_node(target_ip, is_tgt=True)
    mid_nodes = [
        _make_vuln_node(ip)
        for ip in sorted(all_node_ips - {source_ip, target_ip})
    ]
    nodes_out = [src_node] + mid_nodes + [tgt_node]

    # ── Build edges ─────────────────────────────────────────────────────────
    edges_out: List[VulnEdge] = []
    edge_counter = 0

    for rule, is_forward in matching_rules:
        port_str = rule.dest_port or rule.source_port or "any"
        stored_risk = risk_map.get(str(rule.id), 0.0)
        base_risk, method, fixes = _port_details(port_str)
        final_risk = max(stored_risk, base_risk * 0.75)

        e_src_ip = source_ip if is_forward else target_ip
        e_tgt_ip = target_ip if is_forward else source_ip

        if mid_nodes:
            # Route through firewall: source → fw → target
            fw_id = mid_nodes[0].id
            edge_counter += 1
            edges_out.append(VulnEdge(
                id=f"e{edge_counter}a_{rule.id}",
                source_node=_node_id(e_src_ip),
                target_node=fw_id,
                rule_name=rule.rule_name or f"Rule {str(rule.id)[:8]}",
                port=port_str,
                protocol=rule.protocol or "any",
                risk_score=round(final_risk, 1),
                risk_level=_risk_str(final_risk),
                compromise_method=method,
                compromisability=round(min(final_risk, 10.0), 1),
                remediations=fixes,
            ))
            edge_counter += 1
            edges_out.append(VulnEdge(
                id=f"e{edge_counter}b_{rule.id}",
                source_node=fw_id,
                target_node=_node_id(e_tgt_ip),
                rule_name=rule.rule_name or f"Rule {str(rule.id)[:8]}",
                port=port_str,
                protocol=rule.protocol or "any",
                risk_score=round(final_risk * 0.8, 1),
                risk_level=_risk_str(final_risk * 0.8),
                compromise_method=f"Post-firewall traversal: {method}",
                compromisability=round(min(final_risk * 0.8, 10.0), 1),
                remediations=fixes,
            ))
        else:
            edge_counter += 1
            edges_out.append(VulnEdge(
                id=f"e{edge_counter}_{rule.id}",
                source_node=_node_id(e_src_ip),
                target_node=_node_id(e_tgt_ip),
                rule_name=rule.rule_name or f"Rule {str(rule.id)[:8]}",
                port=port_str,
                protocol=rule.protocol or "any",
                risk_score=round(final_risk, 1),
                risk_level=_risk_str(final_risk),
                compromise_method=method,
                compromisability=round(min(final_risk, 10.0), 1),
                remediations=fixes,
            ))

    # ── Summary metrics ─────────────────────────────────────────────────────
    path_exists = len(edges_out) > 0
    overall_risk = max((e.risk_score for e in edges_out), default=0.0)
    risk_level = _risk_str(overall_risk)
    hop_count = len(matching_rules)
    src_label = _label(source_ip, topo_nodes)
    tgt_label = _label(target_ip, topo_nodes)

    if not path_exists:
        summary = (
            f"No active allow rules were found that permit traffic between "
            f"{src_label} ({source_ip}) and {tgt_label} ({target_ip}). "
            "Verify that explicit deny rules are in place to ensure the path remains blocked."
        )
    else:
        top_edge = max(edges_out, key=lambda e: e.risk_score)
        summary = (
            f"{hop_count} firewall rule{'s' if hop_count != 1 else ''} permit traffic between "
            f"{src_label} ({source_ip}) and {tgt_label} ({target_ip}). "
            f"The highest-risk connection allows port {top_edge.port} with a risk score of "
            f"{overall_risk:.1f}/10 ({risk_level.upper()})."
        )

    # ── Build IPEntry helpers ───────────────────────────────────────────────
    def _ip_entry(ip: str) -> IPEntry:
        topo = _topo_for_ip(ip, topo_nodes)
        return IPEntry(
            ip=ip,
            label=_label(ip, topo_nodes),
            zone=topo.zone if topo else None,
            device_type=topo.device_type if topo else None,
            is_firewall=(topo.device_type or "").lower() == "firewall" if topo else False,
        )

    return IPVulnerabilityResponse(
        source=_ip_entry(source_ip),
        target=_ip_entry(target_ip),
        nodes=nodes_out,
        edges=edges_out,
        overall_risk=overall_risk,
        risk_level=risk_level,
        path_exists=path_exists,
        hop_count=hop_count,
        summary=summary,
        source_found=source_found,
        target_found=target_found,
    )


# ── Endpoint 3: CSV + XML driven attack surface analysis ──────────────────────

class AttackSurfacePortDetail(BaseModel):
    port: str
    service: str
    protocol: str
    access_type: str
    base_risk: float
    modifier: float
    total: float
    lateral_movement: bool
    attack_vector: str
    explanation: str


class AttackSurfaceGraphNode(BaseModel):
    id: str
    ip: str
    is_source: bool
    is_target: bool


class AttackSurfaceGraphEdge(BaseModel):
    source: str
    target: str
    port: str
    protocol: str
    risk_score: float
    access_type: str


class AttackSurfaceGraphResponse(BaseModel):
    nodes: List[AttackSurfaceGraphNode]
    edges: List[AttackSurfaceGraphEdge]


class AttackSurfaceResponse(BaseModel):
    source_ip: str
    destination_ip: str
    path_exists: bool
    risk_score: float
    risk_level: str
    allowed_ports: List[AttackSurfacePortDetail]
    explanation: List[str]
    lateral_movement_risk: str          # None / Possible / High
    lateral_movement_paths: List[str]
    attack_vectors: List[str]
    bidirectional_exposure: bool
    graph: AttackSurfaceGraphResponse


def _to_attack_surface_response(result: AttackSurfaceResult) -> AttackSurfaceResponse:
    """Convert engine dataclasses to Pydantic response model."""
    return AttackSurfaceResponse(
        source_ip=result.source_ip,
        destination_ip=result.destination_ip,
        path_exists=result.path_exists,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        allowed_ports=[
            AttackSurfacePortDetail(
                port=p.port,
                service=p.service,
                protocol=p.protocol,
                access_type=p.access_type,
                base_risk=p.base_risk,
                modifier=p.modifier,
                total=p.total,
                lateral_movement=p.lateral_movement,
                attack_vector=p.attack_vector,
                explanation=p.explanation,
            )
            for p in result.allowed_ports
        ],
        explanation=result.explanation,
        lateral_movement_risk=result.lateral_movement_risk,
        lateral_movement_paths=result.lateral_movement_paths,
        attack_vectors=result.attack_vectors,
        bidirectional_exposure=result.bidirectional_exposure,
        graph=AttackSurfaceGraphResponse(
            nodes=[
                AttackSurfaceGraphNode(
                    id=n.id, ip=n.ip,
                    is_source=n.is_source, is_target=n.is_target,
                )
                for n in result.graph.nodes
            ],
            edges=[
                AttackSurfaceGraphEdge(
                    source=e.source, target=e.target,
                    port=e.port, protocol=e.protocol,
                    risk_score=e.risk_score, access_type=e.access_type,
                )
                for e in result.graph.edges
            ],
        ),
    )


class AttackSurfaceRequest(BaseModel):
    source_ip: str
    target_ip: str
    csv_path: Optional[str] = None   # override defaults if needed
    xml_path: Optional[str] = None


@router.post("/attack-surface", response_model=AttackSurfaceResponse)
async def analyze_attack_surface(req: AttackSurfaceRequest) -> AttackSurfaceResponse:
    """
    CSV + XML driven attack surface analysis between two IPs.

    Uses:
      · complyguard_test.csv  — firewall interaction data
          (source_ip, destination_ip, port, protocol, access_type)
      · complyguard_ultra_complete.xml — risk weight model
          (<interactionRiskModel> section)

    Returns a scored breakdown per open port/connection including:
      · Base risk from XML weights + access_type modifier
      · Aggregated total risk score and level (Low/Medium/High/Critical)
      · Per-port explanation and attack vector
      · Lateral movement classification (None/Possible/High)
      · Bidirectional exposure flag
      · Simple graph (nodes = IPs, edges = allowed connections)
    """
    csv_path = req.csv_path or _DEFAULT_CSV_PATH
    xml_path = req.xml_path or _DEFAULT_XML_PATH

    # Run in a thread so the async event loop is not blocked during file I/O
    result: AttackSurfaceResult = await asyncio.to_thread(
        run_attack_surface_analysis,
        req.source_ip.strip(),
        req.target_ip.strip(),
        csv_path,
        xml_path,
    )

    return _to_attack_surface_response(result)
