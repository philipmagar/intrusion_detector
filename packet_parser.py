"""
Packet Parser and Security Event Normalizer for Scapy Packets.

Converts raw Scapy captured network packets into standardized security events
containing source IP, destination IP, ports, protocol, packet size, flags,
and timestamp.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import time
from typing import Optional, List, Dict, Any, Union

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Packet
except ImportError:
    # Allow running in environments where scapy might be imported lazily
    Packet = Any
    IP = TCP = UDP = ICMP = IPv6 = ARP = Ether = None


# Mapping of TCP flag characters to standard human-readable flag names
TCP_FLAG_MAPPINGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}


@dataclass
class SecurityEvent:
    """
    Standardized security event schema representing a network packet.
    """
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    flags: Optional[str]
    timestamp: str
    flags_list: Optional[List[str]] = None
    timestamp_epoch: Optional[float] = None
    summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert security event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


def parse_tcp_flags(flags_val) -> tuple[str, List[str]]:
    """
    Parses TCP flags into a concise string and a list of standard flag names.
    e.g., 'SA' -> ('SYN+ACK', ['SYN', 'ACK']) or ('SA', ['SYN', 'ACK'])
    """
    if flags_val is None:
        return "", []

    # Scapy FlagValue or string or int
    flag_str = str(flags_val).strip()
    flag_names = []

    for char in flag_str:
        if char in TCP_FLAG_MAPPINGS:
            flag_names.append(TCP_FLAG_MAPPINGS[char])
        elif char not in ('', '0'):
            flag_names.append(char)

    if not flag_names and flag_str:
        flag_names = [flag_str]

    formatted_flags = "+".join(flag_names) if flag_names else flag_str
    return formatted_flags, flag_names


def packet_to_security_event(packet: Any) -> SecurityEvent:
    """
    Converts a captured Scapy packet into a standardized SecurityEvent.

    Extracted fields:
    - src_ip: Source IP address (IPv4 / IPv6 / ARP sender IP)
    - dst_ip: Destination IP address (IPv4 / IPv6 / ARP target IP)
    - src_port: Source port (TCP/UDP) or None
    - dst_port: Destination port (TCP/UDP) or None
    - protocol: Protocol name (TCP, UDP, ICMP, ARP, IPv6-ICMP, etc.)
    - packet_size: Total packet size in bytes
    - flags: Formatted TCP flags (e.g. 'SYN', 'SYN+ACK', 'RST') or None
    - timestamp: ISO-formatted timestamp string (YYYY-MM-DD HH:MM:SS)
    - flags_list: List of parsed flags (e.g. ['SYN', 'ACK'])
    - timestamp_epoch: Float UNIX epoch timestamp
    - summary: Scapy packet summary
    """
    # 1. Packet Size
    try:
        packet_size = len(packet)
    except Exception:
        packet_size = 0

    # 2. Timestamp
    pkt_time = getattr(packet, 'time', None)
    if pkt_time is not None:
        try:
            timestamp_epoch = float(pkt_time)
        except (ValueError, TypeError):
            timestamp_epoch = time.time()
    else:
        timestamp_epoch = time.time()

    timestamp = datetime.fromtimestamp(timestamp_epoch).strftime("%Y-%m-%d %H:%M:%S")

    # 3. IP / Network Layer Parsing
    src_ip = None
    dst_ip = None
    protocol = "UNKNOWN"
    src_port = None
    dst_port = None
    flags_str = None
    flags_list = None

    if IP and packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "IP"
    elif IPv6 and packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        src_ip = ipv6_layer.src
        dst_ip = ipv6_layer.dst
        protocol = "IPv6"
    elif ARP and packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        dst_ip = arp_layer.pdst
        protocol = "ARP"

    # 4. Transport Layer Parsing
    if TCP and packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flags_str, flags_list = parse_tcp_flags(tcp_layer.flags)
    elif UDP and packet.haslayer(UDP):
        udp_layer = packet[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
    elif ICMP and packet.haslayer(ICMP):
        protocol = "ICMP"
    elif IPv6 and packet.haslayer("ICMPv6EchoRequest"):
        protocol = "ICMPv6"
    elif IPv6 and packet.haslayer("ICMPv6EchoReply"):
        protocol = "ICMPv6"

    # 5. Summary
    try:
        summary_text = packet.summary() if hasattr(packet, 'summary') else f"{protocol} {src_ip}->{dst_ip}"
    except Exception:
        summary_text = f"{protocol} packet"

    return SecurityEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=packet_size,
        flags=flags_str,
        flags_list=flags_list,
        timestamp=timestamp,
        timestamp_epoch=timestamp_epoch,
        summary=summary_text,
    )
