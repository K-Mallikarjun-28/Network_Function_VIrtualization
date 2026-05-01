"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
File        : validator.py
Description : Input validation for IP addresses, ports, and protocols
=============================================================================
"""

import ipaddress
import re


class Validator:
    """
    Validates all user inputs before they enter the firewall engine.
    Bad inputs should be rejected early — garbage in, garbage out.
    """

    SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "SSH"}

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if a string is a valid IPv4 address.
        Example: "192.168.1.1" → True | "999.0.0.1" → False
        """
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_port(port) -> bool:
        """
        Port must be an integer in the range 1–65535.
        Port 0 is reserved; ports > 65535 don't exist.
        """
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_protocol(protocol: str) -> bool:
        """Check if the protocol is one we support."""
        return protocol.upper() in Validator.SUPPORTED_PROTOCOLS

    @staticmethod
    def is_valid_subnet(subnet: str) -> bool:
        """
        Validate CIDR notation subnet.
        Example: "192.168.0.0/24" → True | "999.0.0.0/33" → False
        """
        try:
            ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_packet_input(cls, ip: str, port: str, protocol: str) -> tuple:
        """
        Validate all three fields for a packet.
        Returns (is_valid: bool, error_message: str)
        """
        if not cls.is_valid_ip(ip):
            return False, f"Invalid IP address: '{ip}'"
        if not cls.is_valid_port(port):
            return False, f"Invalid port: '{port}' (must be 1–65535)"
        if not cls.is_valid_protocol(protocol):
            return False, (f"Unsupported protocol: '{protocol}'. "
                           f"Supported: {', '.join(cls.SUPPORTED_PROTOCOLS)}")
        return True, "OK"
