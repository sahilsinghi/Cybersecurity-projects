import argparse
from core.logger import setup_logger
from core.sniffer import start_sniffer

def parse_args():
    p = argparse.ArgumentParser(description="Personal Firewall (sniffer mode)")
    p.add_argument("--iface", required=True, help="Network interface (e.g. eth0, ens33, wlan0)")
    p.add_argument("--bpf", default=None, help="Optional BPF filter (e.g. 'tcp or udp', 'port 53')")
    p.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    return p.parse_args()

def main():
    args = parse_args()
    logger = setup_logger()
    logger.info(f"Starting sniffer on {args.iface} (filter={args.bpf!r}, count={args.count})")
    start_sniffer(args.iface, args.bpf, args.count, logger)
    logger.info("Sniffer done.")

if __name__ == "__main__":
    main()
