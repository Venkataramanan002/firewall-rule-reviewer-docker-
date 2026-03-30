import ipaddress
from typing import List, Dict, Any, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database.models import NetworkTopology, FirewallRule, AttackPath, RuleRiskAnalysis
import datetime
import uuid

async def calculate_attack_paths(db: AsyncSession, entry_point: str = "Internet", target: str = "Database Servers", max_hops: int = 10):
    """
    Calculates potential attack paths from entry points to critical targets.
    """
    # Normalize input
    entry_zone_input = entry_point.lower().replace(" ", "_")
    target_zone_input = target.lower().replace(" ", "_")
    
    # 1. Fetch Topology and Rules
    topology_result = await db.execute(select(NetworkTopology))
    nodes = topology_result.scalars().all()
    
    rules_result = await db.execute(select(FirewallRule).where(FirewallRule.is_enabled == True))
    rules = rules_result.scalars().all()
    
    # 2. Build adjacency list based on rules and topology
    graph = {} # zone -> list of (target_zone, rule_id, risk_score)
    
    # Pre-fetch risk scores to use in path scoring
    risk_result = await db.execute(select(RuleRiskAnalysis))
    risk_map = {r.rule_id: float(r.risk_score) for r in risk_result.scalars().all()}
    
    for rule in rules:
        if rule.action.lower() != 'allow':
            continue
            
        src_zones = await get_zones_for_ip(rule.source_ip, nodes)
        dst_zones = await get_zones_for_ip(rule.dest_ip, nodes)
        
        rule_risk = risk_map.get(rule.id, 1.0)
        
        for sz in src_zones:
            sz_norm = sz.lower().replace(" ", "_")
            if sz_norm not in graph:
                graph[sz_norm] = []
            for dz in dst_zones:
                dz_norm = dz.lower().replace(" ", "_")
                if sz_norm != dz_norm:
                    graph[sz_norm].append({
                        "target": dz_norm,
                        "rule_id": str(rule.id),
                        "risk_score": rule_risk,
                        "ports": rule.dest_port
                    })

    # 3. Identify Entry Points and Targets
    # If specific entry/target provided, use them; otherwise use defaults from nodes
    entry_zones = {entry_zone_input} if entry_zone_input != "any" else {n.zone.lower().replace(" ", "_") for n in nodes if n.is_entry_point or n.zone == 'internet_edge'}
    target_zones = {target_zone_input} if target_zone_input != "any" else {n.zone.lower().replace(" ", "_") for n in nodes if n.zone in ['database_servers', 'app_servers', 'core']}
    
    # 4. Find Paths (simple DFS with depth limit)
    all_attack_paths = []
    for start_zone in entry_zones:
        find_paths_dfs(start_zone, target_zones, graph, [], set(), all_attack_paths, depth=0, max_depth=max_hops)
    
    # 5. Save Paths to Database
    paths_to_save = []
    for p in all_attack_paths:
        total_risk = sum(hop['risk_score'] for hop in p['hops'])
        vulnerable_ports = [hop['ports'] for hop in p['hops'] if hop['risk_score'] > 5.0]
        
        # Find weakest link (highest risk rule)
        weakest = max(p['hops'], key=lambda x: x['risk_score'])
        
        path_obj = AttackPath(
            id=str(uuid.uuid4()),
            entry_point=p['start'],
            target=p['end'],
            path_hops=p['hops'],
            total_risk_score=min(total_risk, 10.0),
            risk_level=get_risk_level(total_risk),
            attack_difficulty=max(0.0, 10.0 - (total_risk / len(p['hops']))),
            vulnerable_ports_in_path=vulnerable_ports,
            weakest_link=f"Rule {weakest['rule_id']} allowing {weakest['ports']}",
            calculated_at=datetime.datetime.utcnow()
        )
        paths_to_save.append(path_obj)
    
    db.add_all(paths_to_save)
    await db.commit()
    return len(paths_to_save)

async def get_zones_for_ip(ip_str: str, nodes: List[NetworkTopology]) -> Set[str]:
    """
    Heuristic to map an IP/Network string to topology zones.
    """
    if ip_str.lower() == 'any' or ip_str == '0.0.0.0/0':
        return {'internet_edge'}
        
    matched_zones = set()
    try:
        if '/' not in ip_str:
            ip_obj = ipaddress.ip_address(ip_str)
            for node in nodes:
                if node.ip_address and ipaddress.ip_address(node.ip_address) == ip_obj:
                    matched_zones.add(node.zone)
        else:
            net_obj = ipaddress.ip_network(ip_str, strict=False)
            for node in nodes:
                if node.subnet and ipaddress.ip_network(node.subnet).overlaps(net_obj):
                    matched_zones.add(node.zone)
    except ValueError:
        pass
        
    return matched_zones if matched_zones else {'unknown'}

def find_paths_dfs(current: str, targets: Set[str], graph: Dict, current_path: List, visited: Set, results: List, depth=0, max_depth=10):
    if depth > max_depth: # Limit depth
        return
        
    if current in targets and current_path:
        results.append({
            "start": current_path[0]['from'] if current_path else current,
            "end": current,
            "hops": current_path
        })
        return

    if current in visited:
        return
        
    visited.add(current)
    
    for edge in graph.get(current, []):
        new_hop = {
            "from": current,
            "to": edge['target'],
            "rule_id": edge['rule_id'],
            "risk_score": edge['risk_score'],
            "ports": edge['ports']
        }
        find_paths_dfs(edge['target'], targets, graph, current_path + [new_hop], visited.copy(), results, depth + 1, max_depth)

def get_risk_level(score: float) -> str:
    if score >= 15.0: return "critical" # Paths are cumulative
    if score >= 10.0: return "high"
    if score >= 5.0: return "medium"
    return "low"
