"""
Unit tests for packet_parser.py to verify Scapy packet conversion into standardized security events.
"""

import unittest
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from packet_parser import packet_to_security_event, SecurityEvent


class TestPacketParser(unittest.TestCase):

    def test_tcp_syn_packet(self):
        pkt = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=49152, dport=80, flags="S")
        pkt.time = 1700000000.0

        event = packet_to_security_event(pkt)
        self.assertIsInstance(event, SecurityEvent)
        self.assertEqual(event.src_ip, "192.168.1.50")
        self.assertEqual(event.dst_ip, "10.0.0.1")
        self.assertEqual(event.src_port, 49152)
        self.assertEqual(event.dst_port, 80)
        self.assertEqual(event.protocol, "TCP")
        self.assertIn("SYN", event.flags)
        self.assertIn("SYN", event.flags_list)
        self.assertEqual(event.timestamp_epoch, 1700000000.0)
        self.assertGreater(event.packet_size, 0)
        
        # Test JSON serialization
        event_dict = event.to_dict()
        self.assertEqual(event_dict["src_ip"], "192.168.1.50")
        self.assertIn("protocol", event.to_json())

    def test_tcp_syn_ack_packet(self):
        pkt = IP(src="10.0.0.1", dst="192.168.1.50") / TCP(sport=443, dport=52341, flags="SA")
        event = packet_to_security_event(pkt)

        self.assertEqual(event.src_ip, "10.0.0.1")
        self.assertEqual(event.dst_ip, "192.168.1.50")
        self.assertEqual(event.src_port, 443)
        self.assertEqual(event.dst_port, 52341)
        self.assertEqual(event.protocol, "TCP")
        self.assertIn("SYN", event.flags_list)
        self.assertIn("ACK", event.flags_list)

    def test_udp_packet(self):
        pkt = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        event = packet_to_security_event(pkt)

        self.assertEqual(event.src_ip, "192.168.1.100")
        self.assertEqual(event.dst_ip, "8.8.8.8")
        self.assertEqual(event.src_port, 5353)
        self.assertEqual(event.dst_port, 53)
        self.assertEqual(event.protocol, "UDP")
        self.assertIsNone(event.flags)

    def test_icmp_packet(self):
        pkt = IP(src="192.168.1.1", dst="192.168.1.254") / ICMP(type=8, code=0)
        event = packet_to_security_event(pkt)

        self.assertEqual(event.src_ip, "192.168.1.1")
        self.assertEqual(event.dst_ip, "192.168.1.254")
        self.assertIsNone(event.src_port)
        self.assertIsNone(event.dst_port)
        self.assertEqual(event.protocol, "ICMP")

    def test_ipv6_tcp_packet(self):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=8080, dport=22, flags="F")
        event = packet_to_security_event(pkt)

        self.assertEqual(event.src_ip, "2001:db8::1")
        self.assertEqual(event.dst_ip, "2001:db8::2")
        self.assertEqual(event.src_port, 8080)
        self.assertEqual(event.dst_port, 22)
        self.assertEqual(event.protocol, "TCP")
        self.assertIn("FIN", event.flags_list)

    def test_arp_packet(self):
        pkt = ARP(psrc="192.168.1.1", pdst="192.168.1.2")
        event = packet_to_security_event(pkt)

        self.assertEqual(event.src_ip, "192.168.1.1")
        self.assertEqual(event.dst_ip, "192.168.1.2")
        self.assertEqual(event.protocol, "ARP")


if __name__ == '__main__':
    unittest.main()
