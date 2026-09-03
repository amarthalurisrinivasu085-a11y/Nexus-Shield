"""
NEXUS-SHIELD: Stateful Flow & Session Tracker
Maintains bidirectional connection state across (src_ip, dst_ip, src_port, dst_port, proto).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional, List


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def canonical(self) -> Tuple[str, str, int, int, str]:
        """Returns a bidirectional canonical key so client->server and server->client map to one flow."""
        if (self.src_ip, self.src_port) < (self.dst_ip, self.dst_port):
            return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


@dataclass
class FlowRecord:
    canonical_id: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int = 0
    byte_count: int = 0
    tcp_state: str = "ESTABLISHED"
    is_active: bool = True
    tags: List[str] = field(default_factory=list)


class FlowTracker:
    """Aggregates millions of transient packets into actionable communication flows."""

    def __init__(self, idle_timeout_sec: int = 120):
        self.idle_timeout_sec = idle_timeout_sec
        self.active_flows: Dict[Tuple, FlowRecord] = {}

    def update_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        byte_len: int,
        tcp_flags: Optional[List[str]] = None,
    ) -> FlowRecord:
        now_iso = datetime.now(timezone.utc).isoformat()
        flow_key = FlowKey(src_ip, dst_ip, src_port or 0, dst_port or 0, protocol)
        canonical_key = flow_key.canonical()

        if canonical_key not in self.active_flows:
            # Common server ports are typically lower than ephemeral client ports
            if (dst_port or 0) < (src_port or 0):
                client_ip, client_port = src_ip, src_port
                server_ip, server_port = dst_ip, dst_port
            else:
                client_ip, client_port = dst_ip, dst_port
                server_ip, server_port = src_ip, src_port

            record = FlowRecord(
                canonical_id=f"{client_ip}:{client_port}->{server_ip}:{server_port}/{protocol}",
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
                protocol=protocol,
                start_time=now_iso,
                last_seen=now_iso,
            )
            self.active_flows[canonical_key] = record
        else:
            record = self.active_flows[canonical_key]
            record.last_seen = now_iso

        record.packet_count += 1
        record.byte_count += byte_len

        if tcp_flags:
            if "RST" in tcp_flags:
                record.tcp_state = "RESET"
            elif "FIN" in tcp_flags:
                record.tcp_state = "CLOSED"
            elif "SYN" in tcp_flags and "ACK" not in tcp_flags:
                record.tcp_state = "SYN_SENT"

        return record

    def get_active_flows(self) -> List[FlowRecord]:
        return list(self.active_flows.values())
