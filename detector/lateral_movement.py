"""
NEXUS-SHIELD: Lateral Movement & Attack-Pivot Detector
Tracks directional multi-hop connections over administrative and pivot protocols (SMB, RDP, SSH, WinRM, RPC).
Identifies when a compromised node attempts to pivot to intermediate servers or crown jewel databases.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class LateralAlert:
    source_ip: str
    target_ip: str
    protocol_name: str
    port: int
    hop_chain: List[str]
    timestamp: str
    risk_score: int
    blast_radius_impact: str
    summary: str


class LateralMovementDetector:
    """Detects suspicious multi-hop traversal and workstation-to-workstation administrative pivots."""

    ADMIN_PORTS = {
        445: "SMB/CIFS",
        3389: "RDP",
        22: "SSH",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        135: "MS-RPC",
    }

    def __init__(self, pivot_window_seconds: int = 300):
        self.pivot_window_seconds = pivot_window_seconds
        # Inbound history: target_ip -> list of (src_ip, timestamp, port)
        self.inbound_edges: Dict[str, deque] = defaultdict(deque)
        # Outbound history: src_ip -> list of (target_ip, timestamp, port)
        self.outbound_edges: Dict[str, deque] = defaultdict(deque)

    def record_connection(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[LateralAlert]:
        if dst_port not in self.ADMIN_PORTS:
            return None

        now = time.time()
        proto_name = self.ADMIN_PORTS[dst_port]

        # Record this hop
        self.outbound_edges[src_ip].append((dst_ip, now, dst_port))
        self.inbound_edges[dst_ip].append((src_ip, now, dst_port))

        # Evict old records
        while self.inbound_edges[src_ip] and (now - self.inbound_edges[src_ip][0][1]) > self.pivot_window_seconds:
            self.inbound_edges[src_ip].popleft()

        now_iso = datetime.now(timezone.utc).isoformat()

        # Check if src_ip was recently targeted by an inbound admin connection (Chaining: A -> B -> C)
        for prev_src, prev_time, prev_port in list(self.inbound_edges[src_ip]):
            if prev_src != dst_ip and (now - prev_time) <= self.pivot_window_seconds:
                chain = [prev_src, src_ip, dst_ip]
                alert = LateralAlert(
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    protocol_name=proto_name,
                    port=dst_port,
                    hop_chain=chain,
                    timestamp=now_iso,
                    risk_score=91,
                    blast_radius_impact="CRITICAL (Multi-Hop Compromise Chain)",
                    summary=(
                        f"Multi-hop lateral movement detected: {prev_src} accessed {src_ip}, "
                        f"which then immediately pivoted to {dst_ip} via {proto_name} (Port {dst_port})."
                    ),
                )
                return alert

        # Check workstation-to-workstation anomalous admin activity (typical workstations shouldn't receive SMB/RDP from peers)
        is_peer_pivot = src_ip.startswith("192.168.") and dst_ip.startswith("192.168.") and not dst_ip.endswith(".1")
        if is_peer_pivot and dst_port in {445, 3389}:
            alert = LateralAlert(
                source_ip=src_ip,
                target_ip=dst_ip,
                protocol_name=proto_name,
                port=dst_port,
                hop_chain=[src_ip, dst_ip],
                timestamp=now_iso,
                risk_score=85,
                blast_radius_impact="HIGH (Peer-to-Peer Admin Access)",
                summary=f"Suspicious peer-to-peer administrative pivot from {src_ip} to {dst_ip} over {proto_name}.",
            )
            return alert

        return None
