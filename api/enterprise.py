"""
api/enterprise.py
Deterministic enterprise endpoints for summaries, scoring, topology, and exports.
"""

from __future__ import annotations

import csv
import datetime
import io
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import (
    AttackPath,
    ConfigUpload,
    Connection,
    FirewallRule,
    NetworkTopology,
    RuleRiskAnalysis,
    Threat,
)

router = APIRouter(prefix="/api", tags=["Enterprise"])


class CompromiseNarrativeRequest(BaseModel):
    finding_type: str
    finding_data: Optional[Any] = None
    attack_paths: Optional[List[Any]] = []
    connected_systems: Optional[List[str]] = []
    zone: Optional[str] = ""


class CompromiseNarrativeResponse(BaseModel):
    attacker_profile: str
    discovery_method: str
    attack_steps: List[str]
    systems_compromised: List[str]
    data_at_risk: List[str]
    blast_radius: str
    business_impact: str
    time_to_exploit: str
    detection_difficulty: str
    full_narrative: str


class ExecutiveSummaryResponse(BaseModel):
    summary: str
    risk_score: float
    risk_trend: str
    top_findings: List[Dict[str, Any]]


class ComplianceScore(BaseModel):
    framework: str
    score: float
    status: str
    findings: int
    details: List[str]


class FirewallHealthResponse(BaseModel):
    score: float
    grade: str
    breakdown: Dict[str, float]
    recommendations: List[str]


class AttackSurfaceResponse(BaseModel):
    exposed_ports: int
    internet_facing_rules: int
    crown_jewel_assets: int
    total_attack_paths: int
    critical_paths: int
    entry_points: int


class FirewallTopologyResponse(BaseModel):
    firewalls: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    chain_detected: bool
    chain_details: Optional[str] = None


def _deterministic_compromise_narrative(req: CompromiseNarrativeRequest) -> CompromiseNarrativeResponse:
    finding = req.finding_data if isinstance(req.finding_data, dict) else {}
    risk_level = str(finding.get("risk_level", "high")).lower()
    score = finding.get("risk_score") or finding.get("total_risk_score") or "unknown"
    zone = req.zone or "core network"
    systems = req.connected_systems or []

    profile = (
        "External opportunistic attacker using automated scanning"
        if risk_level in {"critical", "high"}
        else "Internal user with elevated access abusing permissive traffic paths"
    )
    detection = "Hard" if risk_level == "critical" else "Medium"
    exploit_window = "Minutes to a few hours" if risk_level == "critical" else "Hours to days"

    steps = [
        "Enumerate reachable hosts and open ports from the source segment.",
        "Validate service exposure on the permitted rule path and identify weak authentication or patch gaps.",
        "Establish foothold on the first reachable host, then pivot through allowed east-west traffic.",
        "Collect credentials and query sensitive services in downstream zones.",
        "Exfiltrate data over existing allowed channels to reduce detection noise.",
    ]

    compromised = systems[:] if systems else [
        "Source-facing workload in the origin zone",
        "Intermediate application or service host",
        "Target asset reachable through allow rules",
    ]

    data_risk = [
        "Authentication material (user or service credentials)",
        "Operational configuration and network mapping data",
        "Application or business data exposed on reachable services",
    ]

    blast = f"Exposure spans {zone} and adjacent trusted segments; permissive routes can widen impact across multiple hosts."
    impact = (
        f"Risk level {risk_level.upper()} (score: {score}) indicates elevated likelihood of service disruption, "
        "data loss, and compliance reporting obligations."
    )
    narrative = (
        f"Likely attacker profile: {profile}. The attack begins by probing allowed paths in {zone}, "
        "then chaining reachable services to move laterally."
    )

    return CompromiseNarrativeResponse(
        attacker_profile=profile,
        discovery_method="Network and service enumeration on allowed firewall paths",
        attack_steps=steps,
        systems_compromised=compromised,
        data_at_risk=data_risk,
        blast_radius=blast,
        business_impact=impact,
        time_to_exploit=exploit_window,
        detection_difficulty=detection,
        full_narrative=narrative,
    )


@router.post("/compromise-narrative", response_model=CompromiseNarrativeResponse)
async def generate_compromise_narrative(req: CompromiseNarrativeRequest):
    return _deterministic_compromise_narrative(req)


@router.get("/dashboard/executive-summary", response_model=ExecutiveSummaryResponse)
async def get_executive_summary(db: AsyncSession = Depends(get_db)):
    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    medium_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "medium"))
    total_rules_q = await db.execute(select(func.count(FirewallRule.id)))
    paths_q = await db.execute(select(func.count(AttackPath.id)))
    crit_paths_q = await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "critical"))
    avg_risk_q = await db.execute(select(func.avg(RuleRiskAnalysis.risk_score)))
    threats_q = await db.execute(select(func.count(Threat.id)))

    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    medium = medium_q.scalar() or 0
    total_rules = total_rules_q.scalar() or 0
    total_paths = paths_q.scalar() or 0
    crit_paths = crit_paths_q.scalar() or 0
    avg_risk = float(avg_risk_q.scalar() or 0)
    total_threats = threats_q.scalar() or 0

    if total_rules == 0:
        risk_score = 0.0
    else:
        risk_score = min(100, (critical * 25 + high * 15 + medium * 5 + crit_paths * 10) / max(total_rules, 1) * 10)
        risk_score = round(min(risk_score, 100), 1)

    top_findings_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(5)
    )
    top_findings = [
        {
            "rule_name": rule.rule_name or f"Rule {rule.id}",
            "risk_score": float(analysis.risk_score),
            "risk_level": analysis.risk_level,
            "reason": analysis.reason or "Review required",
            "device": rule.device_name,
        }
        for rule, analysis in top_findings_q
    ]

    if critical > 0:
        summary = (
            f"Security posture requires immediate action: {critical} critical and {high} high-risk findings across {total_rules} rules. "
            f"{crit_paths} critical attack paths and {total_threats} detected threats increase breach likelihood. "
            "Prioritize strict access reduction, high-risk rule remediation, and targeted monitoring this cycle."
        )
    elif high > 0:
        summary = (
            f"Security posture is elevated: {high} high-risk and {medium} medium-risk findings across {total_rules} rules. "
            f"{total_paths} attack paths are present and should be reduced through segmentation and least-privilege policy updates. "
            "Address high-risk items first to prevent escalation."
        )
    else:
        summary = (
            f"Security posture is stable with mostly medium/low risk findings across {total_rules} rules. "
            f"Average risk remains {avg_risk:.1f}/10 with {total_threats} logged threats for monitoring. "
            "Maintain recurring reviews and keep deny-by-default and service hardening controls in place."
        )

    risk_trend = "critical" if critical > 2 else "high" if critical > 0 or high > 3 else "medium" if high > 0 else "stable"

    return ExecutiveSummaryResponse(
        summary=summary,
        risk_score=risk_score,
        risk_trend=risk_trend,
        top_findings=top_findings,
    )


@router.get("/compliance-scores", response_model=List[ComplianceScore])
async def get_compliance_scores(db: AsyncSession = Depends(get_db)):
    total_q = await db.execute(select(func.count(FirewallRule.id)))
    total = total_q.scalar() or 0
    if total == 0:
        return []

    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    overly_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "overly_permissive"))
    insecure_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "insecure_service"))
    shadowed_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "shadowed"))

    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    overly = overly_q.scalar() or 0
    insecure = insecure_q.scalar() or 0
    shadowed = shadowed_q.scalar() or 0

    pci_deductions = critical * 15 + high * 8 + overly * 10 + insecure * 5
    pci_score = max(0, min(100, 100 - pci_deductions))
    pci_details = []
    if critical > 0:
        pci_details.append(f"{critical} critical rules violate PCI DSS Req 1.2 (deny by default)")
    if overly > 0:
        pci_details.append(f"{overly} overly permissive rules violate Req 1.3 (restrict traffic)")
    if insecure > 0:
        pci_details.append(f"{insecure} insecure services violate Req 2.2 (secure configurations)")
    if not pci_details:
        pci_details.append("No major PCI DSS violations detected")

    iso_deductions = critical * 12 + high * 6 + shadowed * 4 + insecure * 5
    iso_score = max(0, min(100, 100 - iso_deductions))
    iso_details = []
    if critical > 0:
        iso_details.append(f"{critical} critical findings against A.13 Network Security")
    if shadowed > 0:
        iso_details.append(f"{shadowed} shadowed rules violate A.12 Operations Security")
    if high > 0:
        iso_details.append(f"{high} high-risk rules need A.14 review")
    if not iso_details:
        iso_details.append("Firewall configuration aligns with ISO 27001 controls")

    nist_deductions = critical * 10 + high * 5 + overly * 8 + insecure * 6
    nist_score = max(0, min(100, 100 - nist_deductions))
    nist_details = []
    if critical > 0:
        nist_details.append(f"{critical} critical gaps in PR.AC (Access Control)")
    if overly > 0:
        nist_details.append(f"{overly} findings in PR.PT (Protective Technology)")
    if insecure > 0:
        nist_details.append(f"{insecure} findings in PR.IP (Information Protection)")
    if not nist_details:
        nist_details.append("Configuration meets NIST CSF baseline requirements")

    def status(score: float) -> str:
        if score >= 90:
            return "Compliant"
        if score >= 70:
            return "Partial"
        if score >= 50:
            return "At Risk"
        return "Non-Compliant"

    return [
        ComplianceScore(framework="PCI DSS", score=pci_score, status=status(pci_score), findings=critical + high + overly, details=pci_details),
        ComplianceScore(framework="ISO 27001", score=iso_score, status=status(iso_score), findings=critical + high + shadowed + insecure, details=iso_details),
        ComplianceScore(framework="NIST CSF", score=nist_score, status=status(nist_score), findings=critical + high + overly + insecure, details=nist_details),
    ]


@router.get("/firewall-health", response_model=FirewallHealthResponse)
async def get_firewall_health(db: AsyncSession = Depends(get_db)):
    total_q = await db.execute(select(func.count(FirewallRule.id)))
    total = total_q.scalar() or 0
    if total == 0:
        return FirewallHealthResponse(score=0, grade="N/A", breakdown={}, recommendations=["Upload a firewall configuration to assess health."])

    enabled_q = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == True))
    disabled_q = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == False))
    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    overly_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "overly_permissive"))
    shadowed_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "shadowed"))
    unused_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "unused"))

    enabled = enabled_q.scalar() or 0
    disabled = disabled_q.scalar() or 0
    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    overly = overly_q.scalar() or 0
    shadowed = shadowed_q.scalar() or 0
    unused = unused_q.scalar() or 0

    rule_hygiene = max(0, 100 - (shadowed * 10) - (unused * 8) - (disabled / max(total, 1) * 30))
    risk_posture = max(0, 100 - (critical * 20) - (high * 10) - (overly * 8))
    access_control = max(0, 100 - (overly * 15) - (critical * 12))
    config_quality = max(0, 100 - ((critical + high) / max(total, 1)) * 100)

    overall = round((rule_hygiene * 0.25 + risk_posture * 0.30 + access_control * 0.25 + config_quality * 0.20), 1)
    overall = max(0, min(100, overall))
    grade = "A+" if overall >= 95 else "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D" if overall >= 60 else "F"

    recommendations = []
    if critical > 0:
        recommendations.append(f"Fix {critical} critical-risk rules immediately")
    if overly > 0:
        recommendations.append(f"Tighten {overly} overly permissive rules")
    if shadowed > 0:
        recommendations.append(f"Remove {shadowed} shadowed/redundant rules")
    if unused > 0:
        recommendations.append(f"Review and remove {unused} unused rules")
    if not recommendations:
        recommendations.append("Configuration is healthy - maintain regular reviews")

    return FirewallHealthResponse(
        score=overall,
        grade=grade,
        breakdown={
            "rule_hygiene": round(rule_hygiene, 1),
            "risk_posture": round(risk_posture, 1),
            "access_control": round(access_control, 1),
            "config_quality": round(config_quality, 1),
        },
        recommendations=recommendations,
    )


@router.get("/attack-surface", response_model=AttackSurfaceResponse)
async def get_attack_surface(db: AsyncSession = Depends(get_db)):
    exposed_q = await db.execute(
        select(func.count(func.distinct(FirewallRule.dest_port)))
        .where(FirewallRule.action == "allow")
        .where(FirewallRule.dest_port != "any")
    )
    exposed_ports = exposed_q.scalar() or 0

    internet_facing = (await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.action == "allow"))).scalar() or 0
    crown_jewels = (await db.execute(select(func.count(NetworkTopology.id)))).scalar() or 0
    total_paths = (await db.execute(select(func.count(AttackPath.id)))).scalar() or 0
    crit_paths = (await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "critical"))).scalar() or 0
    entry_points = (await db.execute(select(func.count(NetworkTopology.id)).where(NetworkTopology.is_entry_point == True))).scalar() or 0

    return AttackSurfaceResponse(
        exposed_ports=exposed_ports,
        internet_facing_rules=internet_facing,
        crown_jewel_assets=crown_jewels,
        total_attack_paths=total_paths,
        critical_paths=crit_paths,
        entry_points=entry_points,
    )


@router.get("/firewall-topology", response_model=FirewallTopologyResponse)
async def get_firewall_topology(db: AsyncSession = Depends(get_db)):
    topo_q = await db.execute(select(NetworkTopology))
    nodes = topo_q.scalars().all()

    rules_q = await db.execute(select(FirewallRule))
    rules = rules_q.scalars().all()

    upload_q = await db.execute(select(ConfigUpload).order_by(desc(ConfigUpload.upload_time)).limit(5))
    uploads = upload_q.scalars().all()

    fw_devices: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        dn = node.device_name or "unknown"
        if dn not in fw_devices:
            fw_devices[dn] = {
                "device_name": dn,
                "device_type": node.device_type or "firewall",
                "vendor": "",
                "zones": [],
                "ip_address": str(node.ip_address) if node.ip_address else "-",
                "rules_count": 0,
                "is_entry_point": False,
            }
        if node.zone and node.zone not in fw_devices[dn]["zones"]:
            fw_devices[dn]["zones"].append(node.zone)
        if node.is_entry_point:
            fw_devices[dn]["is_entry_point"] = True

    for rule in rules:
        dn = rule.device_name or "unknown"
        if dn in fw_devices:
            fw_devices[dn]["rules_count"] += 1

    for upload in uploads:
        if upload.vendor:
            for dn in fw_devices:
                if not fw_devices[dn]["vendor"]:
                    fw_devices[dn]["vendor"] = upload.vendor

    firewalls = list(fw_devices.values())
    connections: List[Dict[str, Any]] = []
    fw_list = list(fw_devices.keys())

    if len(fw_list) > 1:
        for i, fw1 in enumerate(fw_list):
            for fw2 in fw_list[i + 1 :]:
                shared_zones = set(fw_devices[fw1]["zones"]) & set(fw_devices[fw2]["zones"])
                if shared_zones:
                    connections.append(
                        {
                            "source": fw1,
                            "target": fw2,
                            "type": "shared_zone",
                            "shared_zones": list(shared_zones),
                            "trust_level": "high",
                        }
                    )
    else:
        zone_set = {n.zone for n in nodes if n.zone}
        seen_pairs = set()
        for rule in rules:
            src = (rule.source_ip or "").strip()
            dst = (rule.dest_ip or "").strip()
            if not src or not dst:
                continue

            src_zones = [z for z in zone_set if z and (z.lower() in src.lower() or src.lower() in z.lower())]
            dst_zones = [z for z in zone_set if z and (z.lower() in dst.lower() or dst.lower() in z.lower())]
            if src == "any":
                src_zones = [z for z in zone_set if z and any(k in z.lower() for k in ["untrust", "internet", "outside", "wan"])] or list(zone_set)[:1]
            if dst == "any":
                dst_zones = list(zone_set)

            for sz in src_zones:
                for dz in dst_zones:
                    if sz == dz:
                        continue
                    pair_key = f"{sz}->{dz}"
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    trust = "low" if (rule.action or "").lower() == "deny" else "high"
                    connections.append(
                        {
                            "source": sz,
                            "target": dz,
                            "type": f"{rule.action or 'allow'}_rule",
                            "shared_zones": [sz, dz],
                            "trust_level": trust,
                        }
                    )

    chain_detected = len(firewalls) > 1 or len({n.zone for n in nodes if n.zone}) > 3
    chain_details = None
    if chain_detected:
        zone_count = len({n.zone for n in nodes if n.zone})
        chain_details = (
            f"Detected {len(firewalls)} firewall device(s) managing {zone_count} security zones. "
            "Multi-zone topology suggests layered perimeter defense."
        )

    return FirewallTopologyResponse(
        firewalls=firewalls,
        connections=connections,
        chain_detected=chain_detected,
        chain_details=chain_details,
    )


@router.get("/export/pdf")
async def export_pdf_report(db: AsyncSession = Depends(get_db)):
    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed. Run: pip install fpdf2")

    rules_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(50)
    )
    rules = [(r, a) for r, a in rules_q]

    paths_q = await db.execute(select(AttackPath).order_by(desc(AttackPath.total_risk_score)).limit(20))
    paths = paths_q.scalars().all()

    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
    total_rules = (await db.execute(select(func.count(FirewallRule.id)))).scalar() or 0
    critical = (await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))).scalar() or 0
    high = (await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))).scalar() or 0

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 40, "", ln=True)
    pdf.cell(0, 15, "Firewall Security Assessment Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.datetime.now().strftime('%B %d, %Y at %H:%M UTC')}", ln=True, align="C")
    pdf.cell(0, 8, "ComplyGuard Security Analysis Platform", ln=True, align="C")
    pdf.cell(0, 30, "", ln=True)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(220, 53, 69)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "  EXECUTIVE SUMMARY", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(4)
    summary_text = (
        f"This assessment analysed {total_rules} firewall rules and identified "
        f"{critical} critical and {high} high-risk vulnerabilities. "
        f"{len(paths)} attack paths were discovered, with {total_threats} active threats detected. "
        "Immediate remediation is recommended for all critical findings."
    )
    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(40, 167, 69)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "  PRIORITISED REMEDIATION ROADMAP", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    priority = 1
    for rule, analysis in rules[:15]:
        if analysis.risk_level not in ("critical", "high"):
            continue
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, f"Priority {priority}: {rule.rule_name or 'Unnamed Rule'}", ln=True)
        pdf.set_font("Helvetica", "", 9)
        if analysis.recommendation:
            pdf.multi_cell(0, 4, f"  {analysis.recommendation}")
        pdf.ln(2)
        priority += 1

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "This report was generated by ComplyGuard Security Analysis Platform.", ln=True, align="C")
    pdf.cell(0, 5, "For questions, contact your security operations team.", ln=True, align="C")

    pdf_bytes = pdf.output()
    buffer = io.BytesIO(pdf_bytes)
    buffer.seek(0)

    filename = f"firewall-security-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/csv")
async def export_csv_report(db: AsyncSession = Depends(get_db)):
    rows_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(1000)
    )
    rows = [(r, a) for r, a in rows_q]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "rule_id",
        "device_name",
        "rule_name",
        "source_ip",
        "dest_ip",
        "protocol",
        "action",
        "risk_score",
        "risk_level",
        "risk_category",
        "reason",
        "recommendation",
    ])

    for rule, analysis in rows:
        writer.writerow([
            str(rule.id),
            rule.device_name,
            rule.rule_name or "",
            rule.source_ip,
            rule.dest_ip,
            rule.protocol,
            rule.action,
            float(analysis.risk_score),
            analysis.risk_level,
            analysis.risk_category or "",
            analysis.reason or "",
            analysis.recommendation or "",
        ])

    data = io.BytesIO(output.getvalue().encode("utf-8"))
    data.seek(0)
    filename = f"firewall-risk-export-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return StreamingResponse(
        data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
