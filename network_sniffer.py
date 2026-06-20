#!/usr/bin/env python3
"""
Basic Network Sniffer — CodeAlpha Cybersecurity Internship Task 1
Author: Rana Muhammad Hateem
Roll No: 2025F-BCNS-136

Description:
    Captures live network packets and displays useful information including
    source/destination IPs, protocols, ports, and payload data.

Requirements:
    pip install scapy

Usage:
    Run with administrator/root privileges:
        Windows : python network_sniffer.py
        Linux   : sudo python3 network_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
from datetime import datetime
import sys
import os


# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
PACKET_COUNT   = 50          # Number of packets to capture (0 = unlimited)
SHOW_PAYLOAD   = True        # Show raw payload bytes
MAX_PAYLOAD    = 80          # Max payload characters to display
LOG_TO_FILE    = True        # Save output to a log file
LOG_FILE       = "capture_log.txt"
FILTER         = ""          # BPF filter e.g. "tcp", "udp port 53", ""


# ─────────────────────────────────────────────
#  Protocol map
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    1  : "ICMP",
    6  : "TCP",
    17 : "UDP",
    58 : "ICMPv6",
}

# Well-known port → service name
PORT_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

packet_index = [0]   # mutable counter accessible inside callback


# ─────────────────────────────────────────────
#  Helper utilities
# ─────────────────────────────────────────────
def get_service(port: int) -> str:
    return PORT_MAP.get(port, str(port))


def format_payload(raw_bytes: bytes) -> str:
    """Return a readable hex + ASCII representation of payload bytes."""
    visible = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_bytes)
    hex_str = raw_bytes.hex()
    preview = f"{hex_str[:MAX_PAYLOAD]}..." if len(hex_str) > MAX_PAYLOAD else hex_str
    ascii_preview = f"{visible[:MAX_PAYLOAD//2]}..." if len(visible) > MAX_PAYLOAD//2 else visible
    return f"HEX [{preview}]  ASCII [{ascii_preview}]"


def separator(char="─", width=70):
    return char * width


# ─────────────────────────────────────────────
#  Packet callback
# ─────────────────────────────────────────────
def process_packet(packet):
    packet_index[0] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    lines = []
    lines.append(separator())
    lines.append(f"  Packet #{packet_index[0]:04d}   [{timestamp}]")
    lines.append(separator("─", 70))

    # ── IP Layer ──────────────────────────────
    if IP in packet:
        ip   = packet[IP]
        proto_name = PROTOCOL_MAP.get(ip.proto, f"Proto-{ip.proto}")

        lines.append(f"  {'Layer':<14}: IP (IPv4)")
        lines.append(f"  {'Source IP':<14}: {ip.src}")
        lines.append(f"  {'Destination IP':<14}: {ip.dst}")
        lines.append(f"  {'Protocol':<14}: {proto_name}  (TTL={ip.ttl}, Size={len(packet)} bytes)")

        # ── TCP ───────────────────────────────
        if TCP in packet:
            tcp = packet[TCP]
            flags = []
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x20: flags.append("URG")
            flag_str = "|".join(flags) if flags else "NONE"

            lines.append(f"  {'Src Port':<14}: {tcp.sport}  [{get_service(tcp.sport)}]")
            lines.append(f"  {'Dst Port':<14}: {tcp.dport}  [{get_service(tcp.dport)}]")
            lines.append(f"  {'TCP Flags':<14}: {flag_str}")
            lines.append(f"  {'Seq / Ack':<14}: Seq={tcp.seq}  Ack={tcp.ack}")

        # ── UDP ───────────────────────────────
        elif UDP in packet:
            udp = packet[UDP]
            lines.append(f"  {'Src Port':<14}: {udp.sport}  [{get_service(udp.sport)}]")
            lines.append(f"  {'Dst Port':<14}: {udp.dport}  [{get_service(udp.dport)}]")
            lines.append(f"  {'UDP Length':<14}: {udp.len} bytes")

        # ── ICMP ──────────────────────────────
        elif ICMP in packet:
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                          8: "Echo Request", 11: "Time Exceeded"}
            type_name = icmp_types.get(icmp.type, f"Type-{icmp.type}")
            lines.append(f"  {'ICMP Type':<14}: {type_name} (code={icmp.code})")

        # ── Payload ───────────────────────────
        if SHOW_PAYLOAD and Raw in packet:
            raw = bytes(packet[Raw].load)
            if raw:
                lines.append(f"  {'Payload':<14}: {format_payload(raw)}")

    else:
        lines.append(f"  Non-IP packet captured (Layer 2 / ARP / Other)")
        lines.append(f"  Summary: {packet.summary()}")

    lines.append("")

    output = "\n".join(lines)
    print(output)

    if LOG_TO_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(output + "\n")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    print(separator("═"))
    print("   Basic Network Sniffer — CodeAlpha Cybersecurity Internship")
    print("   Author : Rana Muhammad Hateem | Roll: 2025F-BCNS-136")
    print(separator("═"))

    # List available interfaces
    interfaces = get_if_list()
    print(f"\n  Available interfaces: {', '.join(interfaces)}")

    count_label = str(PACKET_COUNT) if PACKET_COUNT > 0 else "unlimited"
    filter_label = f'"{FILTER}"' if FILTER else "none (all traffic)"
    print(f"  Capturing  : {count_label} packets")
    print(f"  BPF Filter : {filter_label}")
    if LOG_TO_FILE:
        print(f"  Log file   : {LOG_FILE}")
    print(f"\n  [*] Starting capture... Press Ctrl+C to stop.\n")

    if LOG_TO_FILE:
        with open(LOG_FILE, "w") as f:
            header = (f"Network Sniffer Log — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                      f"Author: Rana Muhammad Hateem | Roll: 2025F-BCNS-136\n"
                      f"{'='*70}\n")
            f.write(header)

    try:
        sniff(
            filter=FILTER,
            prn=process_packet,
            count=PACKET_COUNT,
            store=False,
        )
    except KeyboardInterrupt:
        print(f"\n\n  [!] Capture stopped by user.")
    except PermissionError:
        print("\n  [ERROR] Permission denied — run as Administrator (Windows) or sudo (Linux).")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        sys.exit(1)

    print(f"\n  [✓] Total packets captured : {packet_index[0]}")
    if LOG_TO_FILE:
        print(f"  [✓] Log saved to           : {os.path.abspath(LOG_FILE)}")
    print(separator("═"))


if __name__ == "__main__":
    main()