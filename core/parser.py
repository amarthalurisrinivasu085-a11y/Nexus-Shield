"""
NEXUS-SHIELD: Core Packet & Protocol Parser
Extracts structured telemetry from raw network frames across L2 (Data Link),
L3 (Network), L4 (Transport), and L7 (Application metadata).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import struct
import socket
from typing import Optional, Dict, Any, List


@dataclass
class PacketMetadata:
    timestamp: str
    src_mac: str
    dst_mac: str
    eth_type: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[str] = None
    ip_ttl: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: List[str] = field(default_factory=list)
    payload_len: int = 0
    raw_len: int = 0
    is_dns: bool = False
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    arp_op: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None


class PacketParser:
    """Dissects raw packet byte buffers into normalized PacketMetadata."""

    ETHERTYPE_IPV4 = 0x0800
    ETHERTYPE_ARP  = 0x0806
    ETHERTYPE_IPV6 = 0x86DD

    PROTO_ICMP = 1
    PROTO_TCP  = 6
    PROTO_UDP  = 17

    TCP_FLAGS_MAP = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
    }

    @staticmethod
    def format_mac(raw_bytes: bytes) -> str:
        """Converts 6-byte raw hardware address into colon-separated hex."""
        return ":".join(f"{b:02x}" for b in raw_bytes).upper()

    @staticmethod
    def format_ip(raw_bytes: bytes) -> str:
        """Converts 4-byte packed IPv4 address to standard dotted-quad string."""
        return socket.inet_ntoa(raw_bytes)

    def parse_ethernet_frame(self, raw_data: bytes) -> Optional[PacketMetadata]:
        """Dissects an Ethernet II frame."""
        if len(raw_data) < 14:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        dst_mac_raw, src_mac_raw, eth_type_raw = struct.unpack("!6s6sH", raw_data[:14])
        dst_mac = self.format_mac(dst_mac_raw)
        src_mac = self.format_mac(src_mac_raw)
        payload = raw_data[14:]

        meta = PacketMetadata(
            timestamp=now_iso,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_type=f"0x{eth_type_raw:04X}",
            raw_len=len(raw_data),
            payload_len=len(payload),
        )

        if eth_type_raw == self.ETHERTYPE_IPV4:
            meta.eth_type = "IPv4"
            self._parse_ipv4(payload, meta)
        elif eth_type_raw == self.ETHERTYPE_ARP:
            meta.eth_type = "ARP"
            self._parse_arp(payload, meta)
        elif eth_type_raw == self.ETHERTYPE_IPV6:
            meta.eth_type = "IPv6"

        return meta

    def _parse_arp(self, payload: bytes, meta: PacketMetadata) -> None:
        """Dissects ARP packet (RFC 826)."""
        if len(payload) < 28:
            return
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", payload[:8])
        if hlen == 6 and plen == 4:
            s_mac, s_ip, t_mac, t_ip = struct.unpack("!6s4s6s4s", payload[8:28])
            meta.arp_op = "REQUEST" if op == 1 else "REPLY" if op == 2 else f"OP_{op}"
            meta.arp_sender_mac = self.format_mac(s_mac)
            meta.arp_sender_ip = self.format_ip(s_ip)
            meta.arp_target_mac = self.format_mac(t_mac)
            meta.arp_target_ip = self.format_ip(t_ip)
            meta.src_ip = meta.arp_sender_ip
            meta.dst_ip = meta.arp_target_ip

    def _parse_ipv4(self, payload: bytes, meta: PacketMetadata) -> None:
        """Dissects IPv4 packet header."""
        if len(payload) < 20:
            return
        v_ihl, tos, total_len, identification, flags_frag, ttl, proto, checksum, s_ip, d_ip = struct.unpack(
            "!BBHHHBBH4s4s", payload[:20]
        )
        ihl = (v_ihl & 0x0F) * 4
        if len(payload) < ihl:
            return

        meta.src_ip = self.format_ip(s_ip)
        meta.dst_ip = self.format_ip(d_ip)
        meta.ip_ttl = ttl
        ip_payload = payload[ihl:]

        if proto == self.PROTO_TCP:
            meta.ip_proto = "TCP"
            self._parse_tcp(ip_payload, meta)
        elif proto == self.PROTO_UDP:
            meta.ip_proto = "UDP"
            self._parse_udp(ip_payload, meta)
        elif proto == self.PROTO_ICMP:
            meta.ip_proto = "ICMP"
        else:
            meta.ip_proto = f"PROTO_{proto}"

    def _parse_tcp(self, payload: bytes, meta: PacketMetadata) -> None:
        """Dissects TCP header."""
        if len(payload) < 20:
            return
        src_port, dst_port, seq, ack, offset_reserved, flags, window, check, urg = struct.unpack(
            "!HHIIBBHHH", payload[:20]
        )
        meta.src_port = src_port
        meta.dst_port = dst_port

        active_flags = [name for bit, name in self.TCP_FLAGS_MAP.items() if (flags & bit) != 0]
        meta.tcp_flags = active_flags

    def _parse_udp(self, payload: bytes, meta: PacketMetadata) -> None:
        """Dissects UDP header and extracts DNS metadata if applicable."""
        if len(payload) < 8:
            return
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", payload[:8])
        meta.src_port = src_port
        meta.dst_port = dst_port
        udp_payload = payload[8:]

        # Check for DNS (Port 53)
        if src_port == 53 or dst_port == 53:
            meta.is_dns = True
            self._parse_dns(udp_payload, meta)

    def _parse_dns(self, payload: bytes, meta: PacketMetadata) -> None:
        """Lightweight DNS query name extractor."""
        if len(payload) < 12:
            return
        # Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount < 1:
            return

        offset = 12
        labels = []
        try:
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:  # DNS compression pointer
                    offset += 2
                    break
                offset += 1
                labels.append(payload[offset:offset+length].decode("ascii", errors="replace"))
                offset += length

            if labels:
                meta.dns_query = ".".join(labels)

            if offset + 4 <= len(payload):
                qtype, qclass = struct.unpack("!HH", payload[offset:offset+4])
                type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
                meta.dns_qtype = type_map.get(qtype, f"TYPE_{qtype}")
        except Exception:
            pass
