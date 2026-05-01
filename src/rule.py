"""
=============================================================================
Network Function Virtualization (NFV) - Virtual Firewall Simulation
=============================================================================
File        : rule.py
Description : Defines a single firewall rule with all configurable conditions
=============================================================================
"""


class Rule:
    """
    Represents one firewall rule — a condition-action pair.

    In real firewalls (like iptables or AWS Security Groups), rules define
    what traffic is permitted or denied based on various packet attributes.

    Condition fields (all optional — None means "match anything"):
        src_ip    : Exact IP to match
        subnet    : CIDR subnet to match (e.g., "10.0.0.0/8")
        port      : Specific port number
        protocol  : Network protocol (TCP/UDP/ICMP etc.)
        time_range: Tuple (start_hour, end_hour) in 24h format

    Action field:
        action    : "ALLOW" or "BLOCK"

    Priority:
        Lower number = higher priority (evaluated first)
    """

    VALID_ACTIONS = {"ALLOW", "BLOCK"}

    def __init__(
        self,
        name: str,
        action: str,
        priority: int = 100,
        src_ip: str = None,
        subnet: str = None,
        port: int = None,
        protocol: str = None,
        time_range: tuple = None
    ):
        """
        Define a firewall rule.

        :param name:       Unique descriptive name for the rule
        :param action:     "ALLOW" or "BLOCK"
        :param priority:   Evaluation order — lower = checked first (default 100)
        :param src_ip:     Exact source IP to match (optional)
        :param subnet:     CIDR subnet range to match (optional)
        :param port:       Destination port to match (optional)
        :param protocol:   Protocol to match: TCP, UDP, ICMP, etc. (optional)
        :param time_range: Tuple (start_hour, end_hour) for time-based control
        """
        if action.upper() not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Use ALLOW or BLOCK.")

        self.name = name
        self.action = action.upper()
        self.priority = priority
        self.src_ip = src_ip
        self.subnet = subnet
        self.port = port
        self.protocol = protocol.upper() if protocol else None
        self.time_range = time_range  # e.g., (22, 6) = 10 PM to 6 AM

    def describe(self) -> str:
        """Return a human-readable summary of this rule."""
        conditions = []
        if self.src_ip:
            conditions.append(f"src_ip={self.src_ip}")
        if self.subnet:
            conditions.append(f"subnet={self.subnet}")
        if self.port:
            conditions.append(f"port={self.port}")
        if self.protocol:
            conditions.append(f"protocol={self.protocol}")
        if self.time_range:
            conditions.append(f"time={self.time_range[0]}h-{self.time_range[1]}h")

        cond_str = ", ".join(conditions) if conditions else "ANY"
        return f"[{self.priority}] Rule '{self.name}': IF [{cond_str}] → {self.action}"

    def __repr__(self):
        return self.describe()
