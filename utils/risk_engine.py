import ipaddress
from typing import List, Dict, Any, Optional
from database.models import FirewallRule

def ip_in_network(ip_str: str, network_str: str) -> bool:
    """
    Checks if an IP address or network is contained within another network.
    """
    if network_str.lower() == 'any' or network_str == '0.0.0.0/0':
        return True
    if ip_str.lower() == 'any' or ip_str == '0.0.0.0/0':
        return network_str.lower() == 'any' or network_str == '0.0.0.0/0'
    
    try:
        # Normalize to CIDR
        if '/' not in ip_str:
            ip_str += '/32'
        if '/' not in network_str:
            network_str += '/32'
            
        ip_net = ipaddress.ip_network(ip_str, strict=False)
        target_net = ipaddress.ip_network(network_str, strict=False)
        
        return target_net.supernet_of(ip_net)
    except ValueError:
        return False

def port_in_range(port_str: str, range_str: str) -> bool:
    """
    Checks if a port or port range is contained within another port range.
    """
    if range_str.lower() == 'any' or range_str == '1-65535':
        return True
    if port_str.lower() == 'any' or port_str == '1-65535':
        return range_str.lower() == 'any' or range_str == '1-65535'
        
    try:
        def parse_range(p_str):
            if '-' in p_str:
                start, end = map(int, p_str.split('-'))
                return start, end
            else:
                p = int(p_str)
                return p, p
                
        p_start, p_end = parse_range(port_str)
        r_start, r_end = parse_range(range_str)
        
        return r_start <= p_start and r_end >= p_end
    except (ValueError, TypeError):
        return False

def check_if_shadowed(current_rule: FirewallRule, all_rules: List[FirewallRule]) -> bool:
    """
    A rule is shadowed if a higher priority rule (lower position) matches 
    all traffic that the current rule would match.
    """
    for rule in all_rules:
        # Only check rules with higher priority (lower position) on the same device
        if rule.device_name == current_rule.device_name and rule.rule_position < current_rule.rule_position:
            
            # Check Protocol
            proto_match = (rule.protocol.lower() == 'any' or 
                           rule.protocol.lower() == current_rule.protocol.lower())
            
            if not proto_match:
                continue
                
            # Check Source IP
            src_match = ip_in_network(current_rule.source_ip, rule.source_ip)
            if not src_match:
                continue
                
            # Check Destination IP
            dst_match = ip_in_network(current_rule.dest_ip, rule.dest_ip)
            if not dst_match:
                continue
                
            # Check Destination Port
            port_match = port_in_range(current_rule.dest_port, rule.dest_port)
            if not port_match:
                continue
                
            # If we reach here, all traffic for current_rule is covered by 'rule'
            return True
            
    return False

def calculate_rule_risk(rule: FirewallRule, all_rules: List[FirewallRule], vulnerable_ports: Dict[int, Dict[str, str]]) -> Dict[str, Any]:
    """
    Calculates risk score and reasons based on the scoring algorithm.
    """
    risk_score = 0.0
    reasons = []
    category = "overly_permissive" # Default category
    
    # 1. Source Wildcard Check (max +2 points) 
    if rule.source_ip.lower() == 'any' or rule.source_ip == '0.0.0.0/0': 
        risk_score += 2 
        reasons.append("Source allows ANY IP address") 
    
    # 2. Destination Wildcard Check (max +2 points)  
    if rule.dest_ip.lower() == 'any' or rule.dest_ip == '0.0.0.0/0': 
        risk_score += 2 
        reasons.append("Destination allows ANY IP address") 
    
    # 3. Port Range Size (max +1.5 points) 
    if rule.dest_port.lower() == 'any' or rule.dest_port == '1-65535': 
        risk_score += 1.5 
        reasons.append("Allows all ports") 
    elif '-' in rule.dest_port:
        try:
            start, end = map(int, rule.dest_port.split('-')) 
            if (end - start) > 100: 
                risk_score += 1.0 
                reasons.append(f"Wide port range: {rule.dest_port}")
        except ValueError:
            pass
    
    # 4. Insecure Service Check (max +3 points) 
    insecure_ports = [21, 23, 445, 3389, 1433, 3306, 5432] 
    if rule.action.lower() == 'allow': 
        try: 
            # Check if it's a single port or part of a range
            if '-' in rule.dest_port:
                start, end = map(int, rule.dest_port.split('-'))
                matched_insecure = [p for p in insecure_ports if start <= p <= end]
                if matched_insecure:
                    risk_score += 3
                    services = [vulnerable_ports[p]['service'] for p in matched_insecure]
                    reasons.append(f"Allows insecure services in range: {', '.join(services)}")
                    category = "insecure_service"
            else:
                port_num = int(rule.dest_port) 
                if port_num in insecure_ports: 
                    risk_score += 3 
                    service = vulnerable_ports[port_num]['service'] 
                    reasons.append(f"Allows vulnerable service: {service} on port {port_num}")
                    category = "insecure_service"
        except: 
            pass 
    
    # 5. Unused Rule Check (max +1 point) 
    if rule.hit_count == 0 or rule.last_hit is None: 
        risk_score += 1 
        reasons.append("Rule never used (unused)")
        category = "unused"
    
    # 6. Shadowed Rule Check (max +2 points) 
    shadowed = check_if_shadowed(rule, all_rules) 
    if shadowed: 
        risk_score += 2 
        reasons.append("Shadowed by higher priority rule")
        category = "shadowed"
    
    # Cap at 10 
    risk_score = min(risk_score, 10.0)
    
    # Determine Level and Color
    if risk_score >= 9.0:
        level = "critical"
        color = "red"
    elif risk_score >= 6.0:
        level = "high"
        color = "orange"
    elif risk_score >= 3.0:
        level = "medium"
        color = "yellow"
    else:
        level = "low"
        color = "green"
        
    return {
        "rule_id": rule.id,
        "risk_score": risk_score,
        "risk_level": level,
        "risk_category": category,
        "reason": "; ".join(reasons),
        "cvss_color": color,
        "recommendation": generate_recommendation(category, level, reasons)
    }

def generate_recommendation(category: str, level: str, reasons: List[str]) -> str:
    """
    Generates a basic recommendation based on findings.
    """
    if category == "shadowed":
        return "Delete this rule as it is covered by a higher priority rule, or move it above the shadowing rule if intended."
    if category == "unused":
        return "Review if this rule is still needed. If not, disable or delete it to reduce attack surface."
    if category == "insecure_service":
        return "Replace insecure protocol with a secure alternative (e.g., SSH instead of Telnet, SFTP instead of FTP)."
    if category == "overly_permissive":
        return "Restrict source/destination to specific IP addresses or subnets instead of 'any'."
    
    return "Apply principle of least privilege to this rule."
