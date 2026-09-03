"""
NEXUS-SHIELD: Real-Time Port & Network Scan Detector
Detects horizontal reconnaissance (subnet sweeping) and vertical reconnaissance
(probing sequential or top common ports on a single host within a sliding window).
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ScanAlert:
    alert_type: str  # VERTICAL_SCAN, HORIZONTAL_SWEEP
    source_ip: str
    target_ips: List[str]
    ports_targeted: List[int]
    timestamp: str
    risk_score: int
    summary: str


class PortScanDetector:
    """Sliding-window scan detection engine."""

    def __init__(self, port_threshold: int = 8, ip_threshold: int = 5, window_seconds: int = 15):
        self.port_threshold = port_threshold
        self.ip_threshold = ip_threshold
        self.window_seconds = window_seconds

        # Map: src_ip -> deque of (timestamp, target_ip, target_port)
        self.activity_log: Dict[str, deque] = defaultdict(deque)
        self.recent_alerts: List[ScanAlert] = []

    def record_attempt(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[ScanAlert]:
        now = time.time()
        log = self.activity_log[src_ip]

        # Evict events outside sliding window
        while log and (now - log[0][0]) > self.window_seconds:
            log.popleft()

        log.append((now, dst_ip, dst_port))

        # Analyze current window
        target_ips: Set[str] = set()
        ports_per_target: Dict[str, Set[int]] = defaultdict(set)
        total_unique_ports: Set[int] = set()

        for _, target, port in log:
            target_ips.add(target)
            ports_per_target[target].add(port)
            total_unique_ports.add(port)

        now_iso = datetime.now(timezone.utc).isoformat()

        # Check Vertical Scan (Single host, multiple ports)
        for target, ports in ports_per_target.items():
            if len(ports) >= self.port_threshold:
                alert = ScanAlert(
                    alert_type="VERTICAL_PORT_SCAN",
                    source_ip=src_ip,
                    target_ips=[target],
                    ports_targeted=sorted(list(ports)),
                    timestamp=now_iso,
                    risk_score=72,
                    summary=f"Rapid vertical scan from {src_ip} hitting {len(ports)} ports on {target} in {self.window_seconds}s.",
                )
                self.recent_alerts.append(alert)
                return alert

        # Check Horizontal Sweep (Multiple hosts, same or few ports)
        if len(target_ips) >= self.ip_threshold:
            alert = ScanAlert(
                alert_type="HORIZONTAL_NETWORK_SWEEP",
                source_ip=src_ip,
                target_ips=sorted(list(target_ips)),
                ports_targeted=sorted(list(total_unique_ports)),
                timestamp=now_iso,
                risk_score=78,
                summary=f"Horizontal network sweep from {src_ip} probing {len(target_ips)} endpoints across subnet.",
            )
            self.recent_alerts.append(alert)
            return alert

        return None
