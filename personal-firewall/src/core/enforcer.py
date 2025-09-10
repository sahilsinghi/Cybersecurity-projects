import subprocess

def block_ip(ip: str):
    """Block traffic to a specific destination IP using iptables."""
    cmd = ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
    subprocess.run(cmd, check=False)

def allow_ip(ip: str):
    """(Optional) Allow traffic explicitly (not always needed if default policy is ACCEPT)."""
    cmd = ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"]
    subprocess.run(cmd, check=False)

def reset_rules():
    """Flush all iptables rules (cleanup)."""
    subprocess.run(["sudo", "iptables", "-F"], check=False)

