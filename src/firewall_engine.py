"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
Team Members  : Kiran U P, Harsh Sarda, K Mallikarjun
Topic         : NFV-based Virtual Firewall
File          : firewall_engine.py
Description   : Core firewall rule engine - evaluates packets against rules
=============================================================================
"""

import ipaddress
import datetime
from typing import Optional
from packet import Packet
from rule import Rule
from logger import FirewallLogger


class FirewallEngine:
    """
    The central brain of the Virtual Firewall.
    Processes incoming packets against an ordered list of rules
    and makes ALLOW / BLOCK decisions — just like a real firewall.
    """

    def __init__(self, default_policy: str = "BLOCK"):
        """
        Initialize the firewall with an empty rule set.

        :param default_policy: What to do if no rule matches — "ALLOW" or "BLOCK"
                               Best practice is DEFAULT DENY (BLOCK everything unknown).
        """
        self.rules: list[Rule] = []
        self.default_policy = default_policy.upper()
        self.logger = FirewallLogger()
        print(f"[FIREWALL BOOT] Virtual Firewall started | Default Policy: {self.default_policy}")

    # ------------------------------------------------------------------
    # Rule Management
    # ------------------------------------------------------------------

    def add_rule(self, rule: Rule):
        """Add a new rule and re-sort by priority (lower number = higher priority)."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        print(f"[RULE ADDED] '{rule.name}' | Priority {rule.priority} | Action: {rule.action}")

    def remove_rule(self, rule_name: str):
        """Remove a rule by its unique name."""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        if len(self.rules) < before:
            print(f"[RULE REMOVED] '{rule_name}'")
        else:
            print(f"[WARNING] Rule '{rule_name}' not found.")

    def list_rules(self):
        """Display all active rules in priority order."""
        print("\n" + "=" * 60)
        print(f"{'Priority':<10} {'Name':<25} {'Action':<8}")
        print("=" * 60)
        for r in self.rules:
            print(f"{r.priority:<10} {r.name:<25} {r.action:<8}")
        print("=" * 60 + "\n")

    # ------------------------------------------------------------------
    # Packet Processing — First-Match Rule Execution
    # ------------------------------------------------------------------

    def process_packet(self, packet: Packet) -> str:
        """
        Evaluate a packet against all firewall rules in priority order.
        The FIRST matching rule wins (first-match semantics).
        If no rule matches → apply default policy.

        :param packet: The incoming network packet to evaluate
        :return: "ALLOW" or "BLOCK"
        """
        matched_rule_name = "DEFAULT POLICY"
        decision = self.default_policy

        for rule in self.rules:
            if self._matches(rule, packet):
                decision = rule.action
                matched_rule_name = rule.name
                break  # First match stops further evaluation

        # Log every packet decision for auditing
        self.logger.log(packet, decision, matched_rule_name)

        # Visual output to terminal
        icon = "✅ ALLOW" if decision == "ALLOW" else "🚫 BLOCK"
        print(f"\n[PACKET] {packet.src_ip}:{packet.port} ({packet.protocol})")
        print(f"  ➤ Matched Rule : {matched_rule_name}")
        print(f"  ➤ Decision     : {icon}")

        return decision

    # ------------------------------------------------------------------
    # Matching Logic — Each condition is checked independently
    # ------------------------------------------------------------------

    def _matches(self, rule: Rule, packet: Packet) -> bool:
        """
        Check whether a packet satisfies ALL conditions of a given rule.
        All conditions must be true for the rule to match (AND logic).
        """

        # 1. IP address match (exact)
        if rule.src_ip and rule.src_ip != packet.src_ip:
            return False

        # 2. Port match (exact)
        if rule.port and rule.port != packet.port:
            return False

        # 3. Protocol match (case-insensitive)
        if rule.protocol and rule.protocol.upper() != packet.protocol.upper():
            return False

        # 4. Subnet match — checks if packet IP belongs to a CIDR range
        if rule.subnet:
            try:
                network = ipaddress.ip_network(rule.subnet, strict=False)
                pkt_ip = ipaddress.ip_address(packet.src_ip)
                if pkt_ip not in network:
                    return False
            except ValueError:
                # Invalid subnet definition in rule — skip this check
                pass

        # 5. Time-based restriction — block/allow only during certain hours
        if rule.time_range:
            current_hour = datetime.datetime.now().hour
            start_h, end_h = rule.time_range
            # Handle overnight ranges like (22, 6) meaning 10 PM to 6 AM
            if start_h <= end_h:
                in_range = start_h <= current_hour < end_h
            else:
                in_range = current_hour >= start_h or current_hour < end_h
            if not in_range:
                return False  # Time condition not satisfied

        return True  # All conditions matched!
