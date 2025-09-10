firewall_rules = []

def add_rule(rule):
    firewall_rules.append(rule)

def reset_rules():
    firewall_rules.clear()

def check_packet(packet):
    proto = getattr(packet, "proto", None)
    for rule in firewall_rules:
        if rule["protocol"] == "ICMP" and proto == 1:  # ICMP protocol = 1
            return "BLOCK"
    return "ALLOW"
