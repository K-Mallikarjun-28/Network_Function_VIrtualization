"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
File        : test_firewall.py
Description : Automated test suite — verifies firewall decisions are correct
Run with    : python -m pytest tests/test_firewall.py -v
             OR: python tests/test_firewall.py
=============================================================================
"""

import sys
import os
import unittest

# Allow imports from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from firewall_engine import FirewallEngine
from packet import Packet
from rule import Rule
from validator import Validator


def build_test_firewall() -> FirewallEngine:
    """Build a fresh firewall instance for each test run."""
    fw = FirewallEngine(default_policy="BLOCK")

    fw.add_rule(Rule("Block Malicious IP",    "BLOCK", priority=1,  src_ip="10.0.0.99"))
    fw.add_rule(Rule("Block Bad Subnet",      "BLOCK", priority=2,  subnet="10.10.0.0/16"))
    fw.add_rule(Rule("Allow HTTPS",           "ALLOW", priority=5,  port=443, protocol="TCP"))
    fw.add_rule(Rule("Allow HTTP",            "ALLOW", priority=6,  port=80,  protocol="TCP"))
    fw.add_rule(Rule("Allow DNS",             "ALLOW", priority=7,  port=53,  protocol="UDP"))
    fw.add_rule(Rule("Allow Internal",        "ALLOW", priority=8,  subnet="192.168.0.0/16"))
    fw.add_rule(Rule("Block Telnet",          "BLOCK", priority=15, port=23, protocol="TCP"))
    fw.add_rule(Rule("Allow Admin SSH",       "ALLOW", priority=20, port=22, protocol="TCP",
                                                        subnet="192.168.1.0/24"))

    return fw


class TestFirewallDecisions(unittest.TestCase):
    """Tests that cover all major firewall decision scenarios."""

    def setUp(self):
        self.fw = build_test_firewall()

    # --- TC1: Known bad IP should always be blocked (highest priority rule)
    def test_01_block_malicious_ip(self):
        pkt = Packet("10.0.0.99", 80, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "BLOCK",
            "Malicious IP 10.0.0.99 must always be blocked regardless of port")

    # --- TC2: IP from blocked subnet
    def test_02_block_suspicious_subnet(self):
        pkt = Packet("10.10.5.22", 443, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "BLOCK",
            "IP from blocked subnet 10.10.0.0/16 must be blocked")

    # --- TC3: HTTPS traffic from external IP should be allowed
    def test_03_allow_https(self):
        pkt = Packet("8.8.8.8", 443, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "ALLOW",
            "HTTPS (port 443, TCP) from any non-blocked IP should be allowed")

    # --- TC4: HTTP traffic should be allowed
    def test_04_allow_http(self):
        pkt = Packet("172.16.0.5", 80, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "ALLOW",
            "HTTP (port 80, TCP) should be allowed")

    # --- TC5: Internal admin SSH — should be allowed
    def test_05_allow_internal_ssh(self):
        pkt = Packet("192.168.1.10", 22, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "ALLOW",
            "SSH from internal 192.168.1.x subnet should be allowed")

    # --- TC6: Telnet is always blocked (insecure)
    def test_06_block_telnet(self):
        pkt = Packet("192.168.3.5", 23, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "BLOCK",
            "Telnet (port 23) is an insecure protocol and must always be blocked")

    # --- TC7: DNS query should be allowed
    def test_07_allow_dns(self):
        pkt = Packet("10.20.1.1", 53, "UDP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "ALLOW",
            "DNS (port 53, UDP) should be allowed")

    # --- TC8: Unknown traffic falls back to default BLOCK policy
    def test_08_default_block(self):
        pkt = Packet("172.30.0.1", 9999, "TCP")
        result = self.fw.process_packet(pkt)
        self.assertEqual(result, "BLOCK",
            "Unknown traffic with no matching rule should fall to default BLOCK policy")

    # --- TC9: Validator rejects bad IP
    def test_09_validator_bad_ip(self):
        valid, _ = Validator.validate_packet_input("999.999.0.1", "80", "TCP")
        self.assertFalse(valid, "Validator should reject invalid IP address")

    # --- TC10: Validator rejects port out of range
    def test_10_validator_port_range(self):
        valid, _ = Validator.validate_packet_input("192.168.1.1", "99999", "TCP")
        self.assertFalse(valid, "Validator should reject port > 65535")


class TestRuleManagement(unittest.TestCase):
    """Tests for adding, removing, and listing rules."""

    def setUp(self):
        self.fw = FirewallEngine(default_policy="BLOCK")

    def test_rule_addition_and_priority_sort(self):
        """Rules should be sorted by priority after addition."""
        self.fw.add_rule(Rule("Rule C", "ALLOW", priority=30, port=80, protocol="TCP"))
        self.fw.add_rule(Rule("Rule A", "BLOCK", priority=10, src_ip="1.2.3.4"))
        self.fw.add_rule(Rule("Rule B", "ALLOW", priority=20, port=443, protocol="TCP"))
        priorities = [r.priority for r in self.fw.rules]
        self.assertEqual(priorities, sorted(priorities),
                         "Rules should be sorted ascending by priority")

    def test_rule_removal(self):
        """Removed rule should no longer affect packet decisions."""
        self.fw.add_rule(Rule("Temp Block", "BLOCK", priority=1, port=80, protocol="TCP"))
        self.fw.add_rule(Rule("Allow HTTP", "ALLOW", priority=5, port=80, protocol="TCP"))

        # Initially blocked
        pkt = Packet("1.2.3.4", 80, "TCP")
        self.assertEqual(self.fw.process_packet(pkt), "BLOCK")

        # After removing high-priority block rule → should now be allowed
        self.fw.remove_rule("Temp Block")
        self.assertEqual(self.fw.process_packet(pkt), "ALLOW")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  NFV VIRTUAL FIREWALL — Automated Test Suite")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
