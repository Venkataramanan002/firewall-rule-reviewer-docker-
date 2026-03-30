from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException, Depends
from contextlib import asynccontextmanager
from pydantic import BaseModel
from api.upload import router as upload_router
from api.enterprise import router as enterprise_router
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, delete
from database.connection import get_db, AsyncSessionLocal, init_db
from database.models import (
    ConfigUpload, FirewallRule, NetworkTopology,
    RuleRiskAnalysis, AttackPath, Connection, Threat, SystemHealth
)
from parsers.config_parsers import PaloAltoXMLParser, CiscoASAParser, FortinetParser
from utils.risk_engine import calculate_rule_risk
from services.data_importer import ingest_data_file
from typing import List, Dict, Any, Optional
import re
import uuid
import datetime
import logging


@asynccontextmanager
async def lifespan(app):
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)
logger = logging.getLogger(__name__)


app.include_router(upload_router)
app.include_router(enterprise_router)
@app.get("/api/health")
async def health_check():
    return {"status": "ok"}


# ── Constants ────────────────────────────────────────────────────────────────

PARSERS = {
    "paloalto": PaloAltoXMLParser(),
    "cisco":    CiscoASAParser(),
    "fortinet": FortinetParser(),
}

VULNERABLE_PORTS = {
    21:   {"service": "FTP",        "risk": "high",     "reason": "Unencrypted credentials"},
    23:   {"service": "Telnet",     "risk": "critical", "reason": "Unencrypted remote access"},
    25:   {"service": "SMTP",       "risk": "medium",   "reason": "Mail relay abuse"},
    80:   {"service": "HTTP",       "risk": "medium",   "reason": "Unencrypted web traffic"},
    445:  {"service": "SMB",        "risk": "high",     "reason": "Ransomware vector (WannaCry, NotPetya)"},
    1433: {"service": "MS-SQL",     "risk": "high",     "reason": "Database exposure"},
    3306: {"service": "MySQL",      "risk": "high",     "reason": "Database exposure"},
    3389: {"service": "RDP",        "risk": "high",     "reason": "Brute force target, ransomware entry"},
    5432: {"service": "PostgreSQL", "risk": "high",     "reason": "Database exposure"},
    8080: {"service": "HTTP-Alt",   "risk": "medium",   "reason": "Unencrypted web traffic"},
    135:  {"service": "RPC",        "risk": "medium",   "reason": "Windows remote exploits"},
    139:  {"service": "NetBIOS",    "risk": "medium",   "reason": "Information disclosure"},
    22:   {"service": "SSH",        "risk": "low",      "reason": "Secure but verify key auth"},
    443:  {"service": "HTTPS",      "risk": "low",      "reason": "Monitor for SSL inspection bypass"},
}


# ── Upload config ─────────────────────────────────────────────────────────────

@app.post("/api/upload-config")
async def upload_config(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db)
):
    if background_tasks is None:
        from fastapi import BackgroundTasks as BT
        background_tasks = BT()

    filename = file.filename
    vendor = "unknown"

    if filename.endswith(".xml"):
        vendor = "paloalto"
    elif filename.endswith(".conf") or "asa" in filename.lower():
        vendor = "cisco"
    elif "forti" in filename.lower():
        vendor = "fortinet"
    elif any(filename.lower().endswith(ext) for ext in [".csv", ".json", ".xlsx", ".xls"]):
        # Auto-route data files through the data importer
        try:
            result = await ingest_data_file(file, db)
            return {
                "upload_id": result.get("upload_id", ""),
                "vendor": "universal",
                "message": "Data file ingested via data importer",
                "processed_rows": result.get("processed_rows", 0),
                "errors_count": result.get("errors_count", 0),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Data ingestion failed: {str(e)}")
    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file. Supported: .xml (Palo Alto), .conf (Cisco ASA), forti*.conf (FortiGate), .csv, .json, .xlsx (traffic data)"
        )

    upload_id = str(uuid.uuid4())
    content = await file.read()

    # Wipe previous data so re-uploads don't duplicate
    await db.execute(delete(RuleRiskAnalysis))
    await db.execute(delete(AttackPath))
    await db.execute(delete(FirewallRule))
    await db.execute(delete(NetworkTopology))
    await db.execute(delete(Connection))
    await db.execute(delete(Threat))
    await db.execute(delete(ConfigUpload))
    await db.commit()

    new_upload = ConfigUpload(
        id=upload_id,
        filename=filename,
        file_size=len(content),
        vendor=vendor,
        ingestion_status="pending",
        progress_percent=0,
        error_messages=[]
    )
    db.add(new_upload)
    await db.commit()

    background_tasks.add_task(
        process_config_background,
        upload_id,
        content.decode("utf-8", errors="ignore")
    )

    return {"upload_id": upload_id, "vendor": vendor}


@app.post("/api/parse-config/{upload_id}")
async def parse_config(
    upload_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(ConfigUpload).where(ConfigUpload.id == upload_id))
    upload = result.scalars().first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    background_tasks.add_task(process_config_background, upload_id)
    return {"message": "Parsing started in background"}


# ── Background processing — does EVERYTHING from the config ───────────────────

async def process_config_background(upload_id: str, content: str = ""):
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(ConfigUpload).where(ConfigUpload.id == upload_id))
            upload = result.scalars().first()
            if not upload:
                logger.error(f"Upload {upload_id} not found")
                return

            upload.ingestion_status = "processing"
            upload.progress_percent = 5
            await db.commit()

            parser = PARSERS.get(upload.vendor)
            if not parser:
                raise Exception(f"No parser for vendor: {upload.vendor}")

            device_name = f"{upload.vendor}-fw-01"

            # ── Step 1: Parse rules ──────────────────────────────────────
            rules_data = parser.parse_rules(content)
            rules_objs = []
            for r in rules_data:
                rule = FirewallRule(
                    device_name=device_name,
                    rule_name=r.get("rule_name"),
                    rule_position=r.get("rule_position"),
                    source_ip=r.get("source_ip", "any"),
                    source_port=r.get("source_port", "any"),
                    dest_ip=r.get("dest_ip", "any"),
                    dest_port=r.get("dest_port", "any"),
                    protocol=r.get("protocol", "any"),
                    action=r.get("action", "deny"),
                    service_name=r.get("service_name"),
                    is_enabled=r.get("is_enabled", True),
                )
                rules_objs.append(rule)

            db.add_all(rules_objs)
            upload.progress_percent = 20
            upload.configs_processed = len(rules_objs)
            await db.commit()

            # ── Step 2: Parse topology ───────────────────────────────────
            topology_data = parser.parse_topology(content)
            topo_objs = []
            for t in topology_data:
                topo = NetworkTopology(
                    device_name=device_name,
                    device_type=t.get("device_type", "firewall"),
                    zone=t.get("zone"),
                    ip_address=t.get("ip_address"),
                    ports_open=t.get("ports_open", []),
                    connected_to=[],
                    is_entry_point=t.get("is_entry_point", False),
                )
                topo_objs.append(topo)

            db.add_all(topo_objs)
            upload.progress_percent = 35
            await db.commit()

            # ── Step 3: Risk analysis on all rules ───────────────────────
            result = await db.execute(select(FirewallRule))
            all_rules = result.scalars().all()

            for rule in all_rules:
                analysis = calculate_rule_risk(rule, all_rules, VULNERABLE_PORTS)
                rra = RuleRiskAnalysis(
                    rule_id=rule.id,
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    risk_category=analysis["risk_category"],
                    reason=analysis["reason"],
                    cvss_color=analysis["cvss_color"],
                    recommendation=analysis["recommendation"],
                    calculated_at=datetime.datetime.utcnow(),
                )
                db.add(rra)

            upload.progress_percent = 55
            await db.commit()

            # ── Step 4: Derive synthetic connections & threats from config ──
            synthetic = parser.derive_synthetic_data(rules_data, topology_data, device_name)
            syn_conns = synthetic.get("connections", [])
            syn_threats = synthetic.get("threats", [])

            for sc in syn_conns:
                conn = Connection(
                    timestamp=datetime.datetime.strptime(sc["timestamp"], "%Y-%m-%d %H:%M:%S") if isinstance(sc["timestamp"], str) else sc["timestamp"],
                    src_ip=sc["src_ip"],
                    dst_ip=sc["dst_ip"],
                    src_port=sc["src_port"],
                    dst_port=sc["dst_port"],
                    protocol=sc["protocol"],
                    action=sc["action"],
                    rule_id=sc.get("rule_id"),
                    bytes_sent=sc.get("bytes_sent"),
                    bytes_received=sc.get("bytes_received"),
                    packets_sent=sc.get("packets_sent"),
                    packets_received=sc.get("packets_received"),
                    app_name=sc.get("app_name"),
                    app_category=sc.get("app_category"),
                    domain=sc.get("domain"),
                    device_name=sc.get("device_name"),
                    zone_from=sc.get("zone_from"),
                    zone_to=sc.get("zone_to"),
                    geo_src_country=sc.get("geo_src_country"),
                    geo_dst_country=sc.get("geo_dst_country"),
                    session_end=datetime.datetime.strptime(sc["session_end"], "%Y-%m-%d %H:%M:%S") if isinstance(sc.get("session_end"), str) else sc.get("session_end"),
                    duration_seconds=sc.get("duration_seconds"),
                    interface_in=sc.get("interface_in"),
                    interface_out=sc.get("interface_out"),
                    threat_detected=sc.get("threat_detected", False),
                )
                db.add(conn)

            for st in syn_threats:
                thr = Threat(
                    timestamp=datetime.datetime.strptime(st["timestamp"], "%Y-%m-%d %H:%M:%S") if isinstance(st["timestamp"], str) else st["timestamp"],
                    device_name=st.get("device_name"),
                    src_ip=st["src_ip"],
                    dst_ip=st["dst_ip"],
                    threat_type=st.get("threat_type"),
                    threat_name=st.get("threat_name"),
                    severity=st.get("severity"),
                    risk_score=st.get("risk_score"),
                )
                db.add(thr)

            upload.progress_percent = 75
            await db.commit()
            logger.info(f"Synthetic data: {len(syn_conns)} connections, {len(syn_threats)} threats")

            # ── Step 5: Calculate attack paths from zone graph ───────────
            result = await db.execute(select(NetworkTopology))
            topo_nodes = result.scalars().all()
            result2 = await db.execute(select(FirewallRule).where(FirewallRule.is_enabled == True))
            enabled_rules = result2.scalars().all()
            result3 = await db.execute(select(RuleRiskAnalysis))
            risk_map = {str(r.rule_id): float(r.risk_score) for r in result3.scalars().all()}

            # Build zone adjacency graph
            zone_names = list({n.zone for n in topo_nodes if n.zone})
            entry_zones = {n.zone for n in topo_nodes if n.is_entry_point}
            if not entry_zones:
                entry_zones = {zone_names[0]} if zone_names else {"internet_edge"}

            # Map zone → connected zones via allow rules
            graph: Dict[str, List[Dict]] = {}
            for rule in enabled_rules:
                if rule.action.lower() != "allow":
                    continue
                src = rule.source_ip if rule.source_ip != "any" else None
                dst = rule.dest_ip if rule.dest_ip != "any" else None

                # Match zones by name fragment
                src_zones = [z for z in zone_names if src and z.lower() in src.lower()] or \
                             ([src] if src else list(entry_zones))
                dst_zones = [z for z in zone_names if dst and z.lower() in dst.lower()] or \
                             ([dst] if dst else zone_names)

                rule_risk = risk_map.get(str(rule.id), 1.0)
                for sz in src_zones:
                    graph.setdefault(sz, [])
                    for dz in dst_zones:
                        if sz != dz:
                            graph[sz].append({
                                "target": dz,
                                "rule_name": rule.rule_name,
                                "port": rule.dest_port,
                                "risk": rule_risk,
                            })

            # Target zones: database / core / app servers
            target_keywords = ["database", "db", "core", "app_server", "application"]
            target_zones = {z for z in zone_names if any(k in z.lower() for k in target_keywords)}
            if not target_zones:
                target_zones = {zone_names[-1]} if zone_names else {"database_servers"}

            # DFS to find paths
            found_paths = []
            def dfs_with_from(current, path_hops, visited, depth=0):
                if depth > 8:
                    return
                if current in target_zones and path_hops:
                    found_paths.append(list(path_hops))
                    return
                if current in visited:
                    return
                visited = visited | {current}
                for edge in graph.get(current, []):
                    hop_with_from = {**edge, "from": current}
                    dfs_with_from(edge["target"], path_hops + [hop_with_from], visited, depth + 1)

            for entry in entry_zones:
                dfs_with_from(entry, [], set())

            for path_hops in found_paths:
                total_risk = min(sum(h["risk"] for h in path_hops), 10.0)
                level = "critical" if total_risk >= 8 else "high" if total_risk >= 6 else "medium" if total_risk >= 3 else "low"
                nodes = [path_hops[0].get("from", list(entry_zones)[0])] + [h["target"] for h in path_hops]

                ap = AttackPath(
                    id=str(uuid.uuid4()),
                    entry_point=nodes[0],
                    target=nodes[-1],
                    path_hops=path_hops,
                    total_risk_score=total_risk,
                    risk_level=level,
                    attack_difficulty=max(0.0, 10.0 - total_risk),
                    vulnerable_ports_in_path=[h["port"] for h in path_hops if h["risk"] > 5],
                    weakest_link=max(path_hops, key=lambda h: h["risk"])["rule_name"] if path_hops else "",
                    calculated_at=datetime.datetime.utcnow(),
                )
                db.add(ap)

            upload.progress_percent = 100
            upload.ingestion_status = "completed"
            upload.completed_at = datetime.datetime.utcnow()
            await db.commit()
            logger.info(f"Config {upload_id} fully processed: {len(rules_objs)} rules, {len(topo_objs)} zones, {len(found_paths)} attack paths")

        except Exception as e:
            logger.error(f"Error processing config {upload_id}: {e}", exc_info=True)
            try:
                result = await db.execute(select(ConfigUpload).where(ConfigUpload.id == upload_id))
                upload = result.scalars().first()
                if upload:
                    upload.ingestion_status = "failed"
                    upload.error_messages = [str(e)]
                    await db.commit()
            except Exception:
                pass


# ── Read endpoints ─────────────────────────────────────────────────────────

@app.get("/api/ingestion-status")
async def get_ingestion_status(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConfigUpload).order_by(desc(ConfigUpload.upload_time)).limit(1))
    latest = result.scalars().first()
    if not latest:
        return {"message": "No uploads found"}
    return {
        "filename": latest.filename,
        "ingestion_progress": latest.progress_percent,
        "configs_processed_count": latest.configs_processed,
        "last_ingestion_time": latest.completed_at or latest.upload_time,
        "total_errors_count": latest.errors_count,
        "total_warnings_count": latest.warnings_count,
        "unsupported_configs_count": latest.unsupported_count,
    }


@app.get("/api/upload-status/{upload_id}")
async def get_upload_status(upload_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConfigUpload).where(ConfigUpload.id == upload_id))
    upload = result.scalars().first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    return {
        "id": str(upload.id),
        "filename": upload.filename,
        "ingestion_status": upload.ingestion_status,
        "progress_percent": upload.progress_percent,
        "configs_processed": upload.configs_processed,
        "errors_count": upload.errors_count,
        "warnings_count": upload.warnings_count,
        "upload_time": upload.upload_time,
        "completed_at": upload.completed_at,
    }


@app.get("/api/config-uploads")
async def list_config_uploads(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ConfigUpload).order_by(desc(ConfigUpload.upload_time)))
    uploads = result.scalars().all()
    return [
        {
            "id": str(u.id),
            "filename": u.filename,
            "ingestion_status": u.ingestion_status,
            "progress_percent": u.progress_percent,
            "upload_time": u.upload_time,
            "completed_at": u.completed_at,
        }
        for u in uploads
    ]


@app.get("/api/topology/summary")
async def get_topology_summary(db: AsyncSession = Depends(get_db)):
    zones_count   = await db.execute(select(func.count(func.distinct(NetworkTopology.zone))))
    rules_count   = await db.execute(select(func.count(FirewallRule.id)))
    firewalls     = await db.execute(select(func.count(NetworkTopology.id)).where(NetworkTopology.device_type == "firewall"))
    routers       = await db.execute(select(func.count(NetworkTopology.id)).where(NetworkTopology.device_type == "router"))
    switches      = await db.execute(select(func.count(NetworkTopology.id)).where(NetworkTopology.device_type == "switch"))
    vlans         = await db.execute(select(func.count(func.distinct(NetworkTopology.vlan_id))))
    subnets       = await db.execute(select(func.count(func.distinct(NetworkTopology.subnet))))
    return {
        "total_zones":          zones_count.scalar() or 0,
        "total_firewall_rules": rules_count.scalar() or 0,
        "total_routing_entries": 0,
        "firewalls_count":      firewalls.scalar() or 0,
        "routers_count":        routers.scalar() or 0,
        "switches_count":       switches.scalar() or 0,
        "vlans_count":          vlans.scalar() or 0,
        "subnets_count":        subnets.scalar() or 0,
    }


@app.get("/api/analytics/summary")
async def get_analytics_summary(db: AsyncSession = Depends(get_db)):
    try:
        total_q   = await db.execute(select(func.count(Connection.id)))
        bytes_s   = await db.execute(select(func.coalesce(func.sum(Connection.bytes_sent), 0)))
        bytes_r   = await db.execute(select(func.coalesce(func.sum(Connection.bytes_received), 0)))
        proto_q   = await db.execute(select(Connection.protocol, func.count(Connection.protocol)).group_by(Connection.protocol))
        protocols = [{"protocol": p or "unknown", "count": c} for p, c in proto_q.all()]
        return {
            "total_connections": total_q.scalar() or 0,
            "total_bytes": int(bytes_s.scalar() or 0) + int(bytes_r.scalar() or 0),
            "protocols": protocols,
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch analytics summary")


@app.get("/api/risk-analysis/summary")
async def get_risk_summary(db: AsyncSession = Depends(get_db)):
    try:
        critical = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
        high     = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
        medium   = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "medium"))
        low      = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "low"))
        shadowed = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "shadowed"))
        unused   = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "unused"))
        insecure = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "insecure_service"))
        perm     = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "overly_permissive"))
        avg      = await db.execute(select(func.avg(RuleRiskAnalysis.risk_score)))
        return {
            "by_level":    {"critical": critical.scalar() or 0, "high": high.scalar() or 0, "medium": medium.scalar() or 0, "low": low.scalar() or 0},
            "by_category": {"shadowed": shadowed.scalar() or 0, "unused": unused.scalar() or 0, "insecure_service": insecure.scalar() or 0, "overly_permissive": perm.scalar() or 0},
            "overall_avg_score": float(avg.scalar() or 0),
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch risk summary")


@app.get("/api/risky-rules")
async def get_risky_rules(min_score: float = 0.0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    try:
        stmt = (
            select(FirewallRule, RuleRiskAnalysis)
            .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
            .where(RuleRiskAnalysis.risk_score >= min_score)
            .order_by(desc(RuleRiskAnalysis.risk_score))
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [
            {
                "id": rule.id,
                "device_name": rule.device_name,
                "rule_name": rule.rule_name,
                "source": f"{rule.source_ip}:{rule.source_port}",
                "destination": f"{rule.dest_ip}:{rule.dest_port}",
                "protocol": rule.protocol,
                "action": rule.action,
                "risk_score": float(analysis.risk_score),
                "risk_level": analysis.risk_level,
                "reason": analysis.reason,
                "recommendation": analysis.recommendation,
                "cvss_color": analysis.cvss_color,
            }
            for rule, analysis in result
        ]
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch risky rules")


@app.get("/api/attack-paths")
async def get_attack_paths(min_risk: float = 0.0, limit: int = 50, db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(AttackPath).order_by(desc(AttackPath.total_risk_score)).limit(limit)
        result = await db.execute(stmt)
        paths = result.scalars().all()
        return [
            {
                "id": str(p.id),
                "entry_point": p.entry_point,
                "target": p.target,
                "hops": len(p.path_hops) if p.path_hops else 0,
                "total_risk_score": float(p.total_risk_score or 0),
                "risk_level": p.risk_level,
                "attack_difficulty": float(p.attack_difficulty or 0),
                "path_nodes": (
                    [p.entry_point] + [h.get("target", "") for h in p.path_hops]
                    if p.path_hops else [p.entry_point, p.target]
                ),
                "path_hops": p.path_hops or [],
                "weakest_link": p.weakest_link,
                "vulnerable_ports": p.vulnerable_ports_in_path or [],
            }
            for p in paths
        ]
    except Exception as e:
        logger.error(f"Attack paths error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch attack paths")


@app.get("/api/attack-paths/summary")
async def get_attack_path_summary(db: AsyncSession = Depends(get_db)):
    try:
        critical = await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "critical"))
        high     = await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "high"))
        avg      = await db.execute(select(func.avg(AttackPath.total_risk_score)))
        return {
            "critical_paths_count":   critical.scalar() or 0,
            "high_risk_paths_count":  high.scalar() or 0,
            "average_path_risk":      float(avg.scalar() or 0),
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch summary")


@app.post("/api/analyze-attack-paths")
async def analyze_attack_paths_trigger(db: AsyncSession = Depends(get_db)):
    """Re-run attack path calculation from existing rules in DB."""
    return {"message": "Attack paths are calculated automatically on config upload."}

@app.get("/api/attack-graph")
async def get_attack_graph(db: AsyncSession = Depends(get_db)):
    """
    Returns the complete network topology as a graph with all nodes and edges.
    Used by the Attack Graph visualization — shows ALL zones and ALL connections
    between them via firewall rules, not just discovered attack paths.
    """
    try:
        # Fetch all zones (nodes)
        topo_result = await db.execute(select(NetworkTopology))
        topo_nodes = topo_result.scalars().all()

        # Fetch all rules with their risk analysis
        rules_result = await db.execute(
            select(FirewallRule, RuleRiskAnalysis)
            .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id, isouter=True)
        )
        rule_rows = rules_result.all()

        # Build node list — one per unique zone
        zone_map: dict = {}
        for node in topo_nodes:
            if node.zone and node.zone not in zone_map:
                zone_map[node.zone] = {
                    "id": node.zone,
                    "label": node.zone.replace("_", " ").title(),
                    "device_name": node.device_name,
                    "device_type": node.device_type,
                    "ip_address": str(node.ip_address) if node.ip_address else "—",
                    "is_entry_point": node.is_entry_point,
                    "is_target": any(k in node.zone.lower() for k in ["database", "db", "core"]),
                    "ports_open": node.ports_open or [],
                }

        # Build edge list — one per allow rule between zones
        edges = []
        seen_edges = set()
        for rule, analysis in rule_rows:
            if not rule.source_ip or not rule.dest_ip:
                continue
            src = rule.source_ip
            dst = rule.dest_ip

            # Match src/dst to known zone names
            src_zones = [z for z in zone_map if z.lower() in src.lower() or src.lower() in z.lower()]
            dst_zones = [z for z in zone_map if z.lower() in dst.lower() or dst.lower() in z.lower()]

            if src == "any":
                src_zones = [z for z in zone_map if zone_map[z]["is_entry_point"]] or list(zone_map.keys())[:1]
            if dst == "any":
                dst_zones = list(zone_map.keys())

            for sz in src_zones:
                for dz in dst_zones:
                    if sz == dz:
                        continue
                    edge_key = f"{sz}→{dz}→{rule.dest_port}"
                    if edge_key in seen_edges:
                        continue
                    seen_edges.add(edge_key)

                    risk = float(analysis.risk_score) if analysis and analysis.risk_score else 1.0
                    edges.append({
                        "id": edge_key,
                        "source": sz,
                        "target": dz,
                        "rule_name": rule.rule_name or "unnamed",
                        "rule_id": str(rule.id),
                        "port": rule.dest_port or "any",
                        "protocol": rule.protocol or "any",
                        "action": rule.action or "allow",
                        "risk_score": risk,
                        "risk_level": (analysis.risk_level if analysis else "low") or "low",
                        "reason": (analysis.reason if analysis else "") or "",
                        "recommendation": (analysis.recommendation if analysis else "") or "",
                        "is_deny": rule.action.lower() == "deny" if rule.action else False,
                    })

        # Also add zones referenced in rules but missing from topology
        for rule, _ in rule_rows:
            for zone_name in [rule.source_ip, rule.dest_ip]:
                if zone_name and zone_name != "any" and zone_name not in zone_map:
                    # Check if it looks like a zone name (not an IP)
                    if not re.match(r"^\d+\.\d+\.\d+\.\d+", zone_name):
                        zone_map[zone_name] = {
                            "id": zone_name,
                            "label": zone_name.replace("_", " ").title(),
                            "device_name": "unknown",
                            "device_type": "firewall",
                            "ip_address": "—",
                            "is_entry_point": any(k in zone_name.lower() for k in ["internet", "untrust", "outside", "wan"]),
                            "is_target": any(k in zone_name.lower() for k in ["database", "db", "core"]),
                            "ports_open": [],
                        }

        return {
            "nodes": list(zone_map.values()),
            "edges": edges,
            "stats": {
                "total_nodes": len(zone_map),
                "total_edges": len(edges),
                "allow_edges": sum(1 for e in edges if not e["is_deny"]),
                "deny_edges": sum(1 for e in edges if e["is_deny"]),
                "high_risk_edges": sum(1 for e in edges if e["risk_score"] >= 6),
            }
        }
    except Exception as e:
        logger.error(f"Attack graph error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to build attack graph")




@app.get("/api/malware-entry-points")
async def get_malware_entry_points(db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(NetworkTopology).where(NetworkTopology.is_entry_point == True))
        nodes = result.scalars().all()
        return [
            {
                "node_id": str(n.id),
                "device_name": n.device_name,
                "zone": n.zone,
                "ip_address": str(n.ip_address) if n.ip_address else "—",
                "is_active_threat_vector": True,
            }
            for n in nodes
        ]
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch entry points")


@app.post("/api/analyze-rules")
async def analyze_rules(background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    background_tasks.add_task(run_risk_analysis_task)
    return {"message": "Risk analysis started"}


async def run_risk_analysis_task():
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(FirewallRule))
            all_rules = result.scalars().all()
            if not all_rules:
                return
            await db.execute(delete(RuleRiskAnalysis))
            await db.commit()
            for rule in all_rules:
                analysis = calculate_rule_risk(rule, all_rules, VULNERABLE_PORTS)
                db.add(RuleRiskAnalysis(
                    rule_id=rule.id,
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    risk_category=analysis["risk_category"],
                    reason=analysis["reason"],
                    cvss_color=analysis["cvss_color"],
                    recommendation=analysis["recommendation"],
                    calculated_at=datetime.datetime.utcnow(),
                ))
            await db.commit()
            logger.info(f"Re-analysed {len(all_rules)} rules")
        except Exception as e:
            logger.error(f"Risk analysis error: {e}")
            await db.rollback()


@app.get("/api/connections")
async def get_connections(limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(Connection).order_by(desc(Connection.timestamp)).limit(limit)
        result = await db.execute(stmt)
        conns = result.scalars().all()
        return [
            {
                "id": str(c.id),
                "timestamp": c.timestamp.strftime("%Y-%m-%d %H:%M:%S") if c.timestamp else "",
                "src_ip": c.src_ip or "—",
                "dst_ip": c.dst_ip or "—",
                "src_port": c.src_port or 0,
                "dst_port": c.dst_port or 0,
                "protocol": (c.protocol or "tcp").upper(),
                "action": (c.action or "allow").capitalize(),
                "bytes_sent": c.bytes_sent or 0,
                "bytes_received": c.bytes_received or 0,
                "app_name": c.app_name or "—",
                "username": c.username or "—",
                "device_name": c.device_name or "—",
                "zone_from": c.zone_from or "—",
                "zone_to": c.zone_to or "—",
                "rule_id": c.rule_id or "—",
                "duration_seconds": c.duration_seconds or 0,
                "threat_detected": c.threat_detected or False,
                "geo_src_country": c.geo_src_country or "—",
                "geo_dst_country": c.geo_dst_country or "—",
                "url": c.url or "",
                "domain": c.domain or "—",
                "interface_in": c.interface_in or "—",
                "interface_out": c.interface_out or "—",
            }
            for c in conns
        ]
    except Exception as e:
        logger.error(f"Connections error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch connections")


@app.get("/api/threats")
async def get_threats(limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(Threat).order_by(desc(Threat.timestamp)).limit(limit)
        result = await db.execute(stmt)
        threats = result.scalars().all()
        return [
            {
                "id": str(t.id),
                "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.timestamp else "",
                "name": t.threat_name or "Unknown Threat",
                "threat_name": t.threat_name or "Unknown Threat",
                "severity": t.severity or "medium",
                "src_ip": t.src_ip or "—",
                "dst_ip": t.dst_ip or "—",
                "threat_type": t.threat_type or "—",
                "risk_score": t.risk_score or 0,
                "device_name": t.device_name or "—",
                "action": "Blocked",
            }
            for t in threats
        ]
    except Exception as e:
        logger.error(f"Threats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch threats")


@app.get("/api/vulnerable-ports")
async def get_vulnerable_ports(db: AsyncSession = Depends(get_db)):
    try:
        # Check which vulnerable ports are actually exposed via allow rules
        rules_q = await db.execute(
            select(FirewallRule, RuleRiskAnalysis)
            .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id, isouter=True)
            .where(FirewallRule.action == "allow")
        )
        rule_rows = rules_q.all()

        topo_q = await db.execute(select(NetworkTopology))
        devices = topo_q.scalars().all()
        zone_map = {d.zone: d.device_name for d in devices}

        results = []
        for port, meta in VULNERABLE_PORTS.items():
            # Find allow rules that explicitly use this port
            matching_rules = []
            exposed_devices = set()
            exposed_zones = set()

            for rule, analysis in rule_rows:
                try:
                    dp = int(rule.dest_port) if rule.dest_port and rule.dest_port != "any" else None
                except (ValueError, TypeError):
                    dp = None

                if dp == port:
                    matching_rules.append(rule.rule_name or str(rule.id))
                    # Map destination zone
                    dst = rule.dest_ip or "any"
                    for zone in zone_map:
                        if zone.lower() in dst.lower() or dst == "any":
                            exposed_zones.add(zone)
                            exposed_devices.add(zone_map[zone])

            # Also check topology ports_open
            for d in devices:
                if isinstance(d.ports_open, list) and port in d.ports_open:
                    exposed_devices.add(d.device_name)
                    if d.zone:
                        exposed_zones.add(d.zone)

            if matching_rules or exposed_devices:
                results.append({
                    "port": port,
                    "service": meta["service"],
                    "risk_level": meta["risk"],
                    "reason": meta["reason"],
                    "exposed_devices": list(exposed_devices),
                    "zones": list(exposed_zones),
                    "matched_rules": matching_rules,
                    "recommendation": "Restrict access or close if unused",
                })

        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: risk_order.get(x["risk_level"], 4))
        return results
    except Exception as e:
        logger.error(f"Vulnerable ports error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch vulnerable ports")


@app.get("/api/remediation")
async def get_remediation(db: AsyncSession = Depends(get_db)):
    try:
        q = await db.execute(
            select(RuleRiskAnalysis, FirewallRule)
            .join(FirewallRule, RuleRiskAnalysis.rule_id == FirewallRule.id)
            .order_by(desc(RuleRiskAnalysis.risk_score))
            .limit(50)
        )
        return [
            {
                "rule_id": str(rule.id),
                "rule_name": rule.rule_name,
                "device_name": rule.device_name,
                "risk_score": float(analysis.risk_score),
                "risk_level": analysis.risk_level,
                "category": analysis.risk_category,
                "recommendation": analysis.recommendation,
            }
            for analysis, rule in q.all()
        ]
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch remediation items")


@app.get("/api/rule-stats")
async def get_rule_stats(db: AsyncSession = Depends(get_db)):
    try:
        total    = await db.execute(select(func.count(FirewallRule.id)))
        by_act   = await db.execute(select(FirewallRule.action, func.count(FirewallRule.id)).group_by(FirewallRule.action))
        enabled  = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == True))
        disabled = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == False))
        return {
            "total": total.scalar() or 0,
            "by_action": {a or "unknown": c for a, c in by_act.all()},
            "enabled": enabled.scalar() or 0,
            "disabled": disabled.scalar() or 0,
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch rule stats")


class ReachabilityRequest(BaseModel):
    source_zone: str

@app.post("/api/analyze-reachability")
async def analyze_reachability(payload: ReachabilityRequest, db: AsyncSession = Depends(get_db)):
    try:
        topo_q = await db.execute(select(NetworkTopology))
        devices = topo_q.scalars().all()

        # Fetch high-risk rules to determine which zones are anomalous
        risk_q = await db.execute(
            select(RuleRiskAnalysis, FirewallRule)
            .join(FirewallRule, RuleRiskAnalysis.rule_id == FirewallRule.id)
            .where(RuleRiskAnalysis.risk_score >= 7)
        )
        high_risk_dest_zones = set()
        for analysis, rule in risk_q.all():
            if rule.dest_ip and rule.dest_ip != "any":
                high_risk_dest_zones.add(rule.dest_ip.lower())

        reachable = []
        for d in devices:
            zone_lower = (d.zone or "").lower()
            is_risky_target = any(zone_lower in z or z in zone_lower for z in high_risk_dest_zones)
            if d.is_entry_point and is_risky_target:
                confidence = "critical"
            elif d.is_entry_point:
                confidence = "high"
            elif is_risky_target or "database" in zone_lower:
                confidence = "medium"
            else:
                confidence = "low"
            reachable.append({
                "id": str(d.id),
                "name": d.device_name,
                "type": d.device_type,
                "zone": d.zone,
                "confidence": confidence,
                "allowed_ports": d.ports_open or [],
                "traffic_volume_30d": 0,
            })

        anomalies = [r["name"] for r in reachable if r["confidence"] == "critical"]
        return {"reachable_devices": reachable, "anomalies": anomalies}
    except Exception as e:
        logger.error(f"Reachability error: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze reachability")


@app.get("/api/system-health")
async def get_system_health(limit: int = 100, db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(SystemHealth).order_by(desc(SystemHealth.timestamp)).limit(limit)
        result = await db.execute(stmt)
        return result.scalars().all()
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch system health")



