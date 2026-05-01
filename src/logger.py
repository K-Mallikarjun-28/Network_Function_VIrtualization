"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
File        : logger.py
Description : Logs every packet decision to terminal and a persistent log file
=============================================================================
"""

import os
import datetime


class FirewallLogger:
    """
    Audit logger for the Virtual Firewall.

    Every packet that passes through the firewall engine gets logged with:
    - Timestamp
    - Source IP, Port, Protocol
    - Which rule matched
    - Final decision (ALLOW / BLOCK)

    Logs are saved to the 'logs/' directory for review and analysis.
    In real NFV deployments, these logs feed into SIEM (Security Information
    and Event Management) systems for threat monitoring.
    """

    def __init__(self, log_dir: str = "../logs"):
        """
        Set up the logger and create log directory if it doesn't exist.
        :param log_dir: Path to directory where log files are stored
        """
        os.makedirs(log_dir, exist_ok=True)
        today = datetime.date.today().strftime("%Y-%m-%d")
        self.log_file = os.path.join(log_dir, f"firewall_{today}.log")

        # Write session start marker
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"  FIREWALL SESSION STARTED : {datetime.datetime.now()}\n")
            f.write(f"{'='*70}\n")

    def log(self, packet, decision: str, matched_rule: str):
        """
        Record a single packet evaluation result.

        :param packet:       The Packet object that was evaluated
        :param decision:     "ALLOW" or "BLOCK"
        :param matched_rule: Name of the rule that caused the decision
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_icon = "ALLOW ✓" if decision == "ALLOW" else "BLOCK ✗"

        log_line = (
            f"[{timestamp}] | "
            f"IP: {packet.src_ip:<16} | "
            f"Port: {packet.port:<6} | "
            f"Protocol: {packet.protocol:<6} | "
            f"Rule: {matched_rule:<25} | "
            f"Decision: {status_icon}\n"
        )

        # Append to daily log file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_line)

    def print_log_path(self):
        print(f"[LOGGER] Log file: {os.path.abspath(self.log_file)}")
