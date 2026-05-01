"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
File        : packet.py
Description : Represents a simulated network packet with all key fields
=============================================================================
"""

import datetime


class Packet:
    """
    Simulates a network packet — the unit of data traveling through a network.
    In real NFV environments, packets carry actual data across virtual links.
    Here we represent them as structured objects for firewall evaluation.
    """

    VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "SSH"}

    def __init__(self, src_ip: str, port: int, protocol: str):
        """
        Create a new packet.

        :param src_ip:    Source IP address (e.g., "192.168.1.10")
        :param port:      Destination port number (0–65535)
        :param protocol:  Network protocol (TCP, UDP, ICMP, etc.)
        """
        self.src_ip = src_ip
        self.port = port
        self.protocol = protocol.upper()
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self):
        return (f"Packet(src_ip='{self.src_ip}', port={self.port}, "
                f"protocol='{self.protocol}', time='{self.timestamp}')")

    def to_dict(self) -> dict:
        """Return packet data as a dictionary (useful for logging/serialization)."""
        return {
            "src_ip": self.src_ip,
            "port": self.port,
            "protocol": self.protocol,
            "timestamp": self.timestamp
        }
