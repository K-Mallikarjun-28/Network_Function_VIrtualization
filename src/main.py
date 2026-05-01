"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
Team Members  : Kiran U P, Harsh Sarda, K Mallikarjun
Topic         : NFV-based Virtual Firewall
File          : main.py
Description   : Main runner — loads rules, runs test cases, and accepts
                live user input for interactive packet testing.
=============================================================================

HOW TO RUN:
    cd src
    python main.py

REQUIREMENTS:
    Python 3.8+   (uses f-strings and type hints)
    No external libraries needed — uses only Python stdlib
=============================================================================
"""

import sys
import os

# Ensure imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firewall_engine import FirewallEngine
from packet import Packet
from rule import Rule
from validator import Validator


def configure_console_encoding():
    """
    Make Unicode console output safer on Windows terminals that default to cp1252.
    Falls back to replacement mode if UTF-8 is not accepted.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                stream.reconfigure(errors="replace")


# =============================================================================
# SECTION 1 — Firewall Setup
# =============================================================================

def build_firewall() -> FirewallEngine:
    """
    Initialize the firewall engine and load all predefined rules.
    Rules are sorted by priority automatically (lower number = first checked).

    Rule Design Philosophy (mirrors real-world firewall design):
      - Block known bad actors first (high priority, low number)
      - Allow trusted services next
      - Block dangerous ports
      - Apply time-based restrictions
      - Default BLOCK everything else
    """

    fw = FirewallEngine(default_policy="BLOCK")

    # ── Priority 1: Block a known malicious IP immediately ──────────────────
    fw.add_rule(Rule(
        name="Block Malicious IP",
        action="BLOCK",
        priority=1,
        src_ip="10.0.0.99"
    ))

    # ── Priority 2: Block an entire suspicious subnet (e.g., dark net range) ─
    fw.add_rule(Rule(
        name="Block Suspicious Subnet",
        action="BLOCK",
        priority=2,
        subnet="10.10.0.0/16"
    ))

    # ── Priority 3: Block SSH brute-force attempts from external range ───────
    fw.add_rule(Rule(
        name="Block External SSH",
        action="BLOCK",
        priority=3,
        port=22,
        protocol="TCP",
        subnet="203.0.113.0/24"   # TEST-NET-3 — used as "untrusted external" example
    ))

    # ── Priority 5: Allow HTTPS web traffic (port 443) ──────────────────────
    fw.add_rule(Rule(
        name="Allow HTTPS",
        action="ALLOW",
        priority=5,
        port=443,
        protocol="TCP"
    ))

    # ── Priority 6: Allow HTTP web traffic (port 80) ────────────────────────
    fw.add_rule(Rule(
        name="Allow HTTP",
        action="ALLOW",
        priority=6,
        port=80,
        protocol="TCP"
    ))

    # ── Priority 7: Allow DNS queries (UDP port 53) ──────────────────────────
    fw.add_rule(Rule(
        name="Allow DNS",
        action="ALLOW",
        priority=7,
        port=53,
        protocol="UDP"
    ))

    # ── Priority 8: Allow internal network traffic (RFC 1918 private range) ──
    fw.add_rule(Rule(
        name="Allow Internal Network",
        action="ALLOW",
        priority=8,
        subnet="192.168.0.0/16"
    ))

    # ── Priority 10: Block all UDP during late-night hours (midnight to 6 AM)
    #    Time-based control — useful in corporate environments
    fw.add_rule(Rule(
        name="Block Midnight UDP Traffic",
        action="BLOCK",
        priority=10,
        protocol="UDP",
        time_range=(0, 6)   # 12:00 AM to 5:59 AM
    ))

    # ── Priority 15: Block telnet (port 23) — deprecated, insecure protocol ──
    fw.add_rule(Rule(
        name="Block Telnet",
        action="BLOCK",
        priority=15,
        port=23,
        protocol="TCP"
    ))

    # ── Priority 20: Allow internal admin SSH (from trusted LAN) ─────────────
    fw.add_rule(Rule(
        name="Allow Admin SSH",
        action="ALLOW",
        priority=20,
        port=22,
        protocol="TCP",
        subnet="192.168.1.0/24"
    ))

    return fw


# =============================================================================
# SECTION 2 — Predefined Test Cases
# =============================================================================

def run_test_cases(fw: FirewallEngine):
    """
    Run 8 structured test cases to validate firewall behaviour.
    Each test represents a real-world network scenario.
    """

    print("\n" + "🔷" * 30)
    print("          PHASE 5: TEST CASES — VIRTUAL FIREWALL")
    print("🔷" * 30)

    tests = [
        # (description, src_ip, port, protocol)
        ("TC1 | Known malicious IP trying to connect",
         "10.0.0.99", 80, "TCP"),

        ("TC2 | Suspicious subnet traffic",
         "10.10.5.22", 443, "TCP"),

        ("TC3 | Normal HTTPS web request from public internet",
         "8.8.8.8", 443, "TCP"),

        ("TC4 | HTTP request (should be allowed)",
         "172.16.0.5", 80, "TCP"),

        ("TC5 | Internal SSH from admin machine",
         "192.168.1.10", 22, "TCP"),

        ("TC6 | External SSH brute-force attempt",
         "203.0.113.55", 22, "TCP"),

        ("TC7 | Telnet connection (insecure, should be blocked)",
         "192.168.2.3", 23, "TCP"),

        ("TC8 | DNS query from any host",
         "10.20.1.1", 53, "UDP"),
    ]

    for desc, ip, port, proto in tests:
        print(f"\n  ── {desc}")
        packet = Packet(src_ip=ip, port=port, protocol=proto)
        fw.process_packet(packet)


# =============================================================================
# SECTION 3 — Interactive User Input Mode
# =============================================================================

def interactive_mode(fw: FirewallEngine):
    """
    Let the user manually test any packet through the firewall.
    Validates all inputs before processing.
    """

    print("\n" + "=" * 60)
    print("  🖥️  INTERACTIVE MODE — Test Your Own Packet")
    print("  (Type 'exit' at any prompt to quit)")
    print("=" * 60)

    supported = ", ".join(Validator.SUPPORTED_PROTOCOLS)

    while True:
        print()
        ip = input("  Enter Source IP   (e.g., 192.168.1.5) : ").strip()
        if ip.lower() == "exit":
            break

        port = input("  Enter Port        (e.g., 443)          : ").strip()
        if port.lower() == "exit":
            break

        protocol = input(f"  Enter Protocol    ({supported}) : ").strip()
        if protocol.lower() == "exit":
            break

        # Validate before processing
        valid, msg = Validator.validate_packet_input(ip, port, protocol)
        if not valid:
            print(f"\n  ❌ INPUT ERROR: {msg}")
            print("  Please try again.\n")
            continue

        packet = Packet(src_ip=ip, port=int(port), protocol=protocol)
        fw.process_packet(packet)

        again = input("\n  Test another packet? (yes/no): ").strip().lower()
        if again not in ("yes", "y"):
            break

    print("\n  [EXIT] Thank you for using the NFV Virtual Firewall Simulator.")


# =============================================================================
# SECTION 4 — Entry Point
# =============================================================================

if __name__ == "__main__":
    configure_console_encoding()

    print("\n" + "=" * 65)
    print("  NFV VIRTUAL FIREWALL SIMULATION")
    print("  Team: Kiran U P | Harsh Sarda | K Mallikarjun")
    print("  Topic: Network Function Virtualization — Security Lab")
    print("=" * 65)

    # Step 1: Build firewall with all rules
    fw = build_firewall()

    # Step 2: Show all loaded rules
    print("\n[LOADED RULES — sorted by priority]")
    fw.list_rules()

    # Step 3: Run predefined test cases
    run_test_cases(fw)

    # Step 4: Show log file location
    fw.logger.print_log_path()

    # Step 5: Switch to interactive mode
    print("\n" + "=" * 65)
    choice = input("\n  Run interactive mode? (yes/no): ").strip().lower()
    if choice in ("yes", "y"):
        interactive_mode(fw)
