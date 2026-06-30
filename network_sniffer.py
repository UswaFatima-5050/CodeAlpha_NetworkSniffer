#!/usr/bin/env python3
"""
CodeAlpha Internship - Task 1
Basic Network Sniffer
Author: Uswa Fatima
Tool: Scapy (Python)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP, Ether
from datetime import datetime
import argparse
import sys
import os

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

LOG_FILE = "capture_log.txt"

def banner():
    print(f"""{CYAN}{BOLD}
CodeAlpha - Basic Network Sniffer
Author: Uswa Fatima | Tool: Scapy
{RESET}
    """)

def log(message: str):
    print(message)
    with open(LOG_FILE, "a") as f:
        clean = message
        for code in [RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA, RESET, BOLD]:
            clean = clean.replace(code, "")
        f.write(clean + "\n")

def format_payload(payload: bytes, max_len: int = 80) -> str:
    try:
        decoded = payload.decode("utf-8", errors="replace")
        decoded = "".join(c if c.isprintable() else "." for c in decoded)
        return decoded[:max_len] + ("..." if len(decoded) > max_len else "")
    except Exception:
        return payload.hex()[:max_len]

def get_protocol_name(proto_num: int) -> str:
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
    return protocols.get(proto_num, f"PROTO-{proto_num}")

packet_count = [0]

def process_packet(pkt):
    packet_count[0] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    sep = f"{BLUE}{'-' * 60}{RESET}"

    log(sep)
    log(f"{BOLD}[#{packet_count[0]:04d}] {YELLOW}{timestamp}{RESET}")

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        log(f"  {MAGENTA}[ARP {op}]{RESET}")
        log(f"  Sender: {GREEN}{arp.psrc}{RESET} ({arp.hwsrc})")
        log(f"  Target: {RED}{arp.pdst}{RESET} ({arp.hwdst})")
        return

    if not pkt.haslayer(IP):
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            log(f"  {CYAN}[ETHERNET]{RESET} {eth.src} -> {eth.dst}  Type: {hex(eth.type)}")
        return

    ip = pkt[IP]
    proto = get_protocol_name(ip.proto)
    log(f"  {CYAN}[IP]{RESET}  {GREEN}{ip.src}{RESET}  ->  {RED}{ip.dst}{RESET}")
    log(f"  Protocol : {YELLOW}{proto}{RESET}  |  TTL: {ip.ttl}  |  Len: {ip.len} bytes")

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = []
        if tcp.flags & 0x02: flags.append("SYN")
        if tcp.flags & 0x10: flags.append("ACK")
        if tcp.flags & 0x01: flags.append("FIN")
        if tcp.flags & 0x04: flags.append("RST")
        if tcp.flags & 0x08: flags.append("PSH")
        flag_str = "|".join(flags) if flags else "NONE"

        log(f"  {BLUE}[TCP]{RESET}  Sport: {tcp.sport}  ->  Dport: {tcp.dport}")
        log(f"  Flags : {YELLOW}{flag_str}{RESET}  |  Seq: {tcp.seq}  |  Ack: {tcp.ack}")

        if tcp.dport == 80 or tcp.sport == 80:
            log(f"  {GREEN}[HTTP TRAFFIC DETECTED]{RESET}")
        if tcp.dport == 443 or tcp.sport == 443:
            log(f"  {GREEN}[HTTPS/TLS TRAFFIC DETECTED]{RESET}")
        if tcp.dport == 22 or tcp.sport == 22:
            log(f"  {MAGENTA}[SSH TRAFFIC DETECTED]{RESET}")

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        log(f"  {BLUE}[UDP]{RESET}  Sport: {udp.sport}  ->  Dport: {udp.dport}  |  Len: {udp.len}")
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dns_name = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            log(f"  {GREEN}[DNS QUERY]{RESET} -> {YELLOW}{dns_name}{RESET}")

    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "TTL Exceeded"}
        icmp_name = icmp_types.get(icmp.type, f"Type-{icmp.type}")
        log(f"  {BLUE}[ICMP]{RESET} {YELLOW}{icmp_name}{RESET}  Code: {icmp.code}")

    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if payload:
            display = format_payload(payload)
            log(f"  {MAGENTA}[PAYLOAD]{RESET} {display}")

def main():
    banner()

    parser = argparse.ArgumentParser(description="CodeAlpha Network Sniffer")
    parser.add_argument("-i", "--iface",   default=None,  help="Network interface (e.g. eth0, wlan0). Default: auto")
    parser.add_argument("-c", "--count",   type=int, default=50, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter",  default="",    help="BPF filter (e.g. 'tcp', 'udp', 'icmp', 'port 80')")
    parser.add_argument("--no-log",        action="store_true",  help="Disable saving to log file")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{RED}[!] Run as root:  sudo python3 network_sniffer.py{RESET}")
        sys.exit(1)

    count_msg = "unlimited" if args.count == 0 else str(args.count)
    iface_msg = args.iface if args.iface else "auto-detect"

    print(f"{GREEN}[*] Interface : {iface_msg}{RESET}")
    print(f"{GREEN}[*] Packets   : {count_msg}{RESET}")
    print(f"{GREEN}[*] Filter    : '{args.filter}' (empty = all traffic){RESET}")
    if not args.no_log:
        print(f"{GREEN}[*] Log file  : {LOG_FILE}{RESET}")
    print(f"{YELLOW}[*] Starting capture... Press Ctrl+C to stop{RESET}\n")

    if not args.no_log:
        with open(LOG_FILE, "w") as f:
            f.write(f"Network Sniffer Log - {datetime.now()}\n{'='*60}\n")

    try:
        sniff(
            iface=args.iface,
            prn=process_packet,
            count=args.count,
            filter=args.filter if args.filter else None,
            store=False
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"{RED}[!] Permission denied. Run with sudo.{RESET}")
        sys.exit(1)

    print(f"\n{GREEN}[OK] Capture complete. Total packets: {packet_count[0]}{RESET}")
    if not args.no_log:
        print(f"{GREEN}[OK] Log saved to: {LOG_FILE}{RESET}")

if __name__ == "__main__":
    main()
