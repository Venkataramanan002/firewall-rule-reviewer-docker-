def parse_tcp_flags(hex_val: str) -> str:
    """
    Parses hex TCP flags (e.g., 0x12) into readable format (e.g., "SYN+ACK").
    """
    if not hex_val:
        return None
    
    try:
        val = int(hex_val, 16)
    except ValueError:
        return hex_val

    flags = []
    if val & 0x01: flags.append("FIN")
    if val & 0x02: flags.append("SYN")
    if val & 0x04: flags.append("RST")
    if val & 0x08: flags.append("PSH")
    if val & 0x10: flags.append("ACK")
    if val & 0x20: flags.append("URG")
    
    return "+".join(flags) if flags else "NONE"
