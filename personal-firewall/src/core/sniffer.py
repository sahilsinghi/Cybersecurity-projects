from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from core.rules import check_packet

def _pkt_to_row(pkt):
    """Extract useful fields from a packet."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src = pkt[IP].src if IP in pkt else "-"
    dst = pkt[IP].dst if IP in pkt else "-"
    proto = (
        "TCP" if TCP in pkt else
        "UDP" if UDP in pkt else
        "ICMP" if ICMP in pkt else
        "OTHER"
    )
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else "-")
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "-")
    length = len(pkt)
    return ts, src, dst, proto, sport, dport, length, pkt

def start_sniffer(iface: str, bpf: str = None, limit: int = 0, logger=None):
    """Sniff packets and log details."""

    def _on_pkt(pkt):
        ts, src, dst, proto, sport, dport, length, pkt_ref = _pkt_to_row(pkt)

        # check verdict from rules
        action = check_packet(pkt_ref)

        msg = f"{action} | {ts} | {src} -> {dst} | {proto} {sport}->{dport} | len={length}"
        if logger:
            logger.info(msg)

        # if block, show enforced
        if action == "BLOCK" and dst != "-":
            if logger:
                logger.info(f"ENFORCED BLOCK on {dst}")

    sniff(
        iface=iface,          # e.g. enp0s1
        filter=bpf,           # None = sniff everything
        prn=_on_pkt,          # callback for each packet
        store=False,
        count=limit
    )

