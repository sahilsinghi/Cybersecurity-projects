from typing import List, Dict

# Firewall rules list
firewall_rules: List[Dict] = []

# Add a new rule
def add_rule(rule: Dict):
    firewall_rules.append(rule)

# Reset all rules
def reset_rules():
    firewall_rules.clear()

# Check packet against rules
def check_packet(packet):
    proto = getattr(packet, "proto", None)

    # Check custom rules first
    for rule in firewall_rules:
        if rule["protocol"] == "ICMP" and proto == 1:  # ICMP proto = 1
            return "BLOCK"

    # Default: allow
    return "ALLOW"

