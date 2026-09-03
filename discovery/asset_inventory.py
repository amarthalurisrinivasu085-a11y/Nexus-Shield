"""
NEXUS-SHIELD: Dynamic Asset Discovery & Inventory
Maintains active device registry, MAC OUI vendor mapping, OS/role profiling,
and containment state.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set


@dataclass
class NetworkAsset:
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Generic Network Device"
    role: str = "Workstation"  # Gateway, Server, Database, Workstation, IoT
    criticality: str = "Medium"  # Critical, High, Medium, Low
    open_ports: Set[int] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    risk_score: int = 0
    status: str = "NORMAL"  # NORMAL, SUSPICIOUS, CONTAINED
    containment_reason: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "role": self.role,
            "criticality": self.criticality,
            "open_ports": sorted(list(self.open_ports)),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk_score": self.risk_score,
            "status": self.status,
            "containment_reason": self.containment_reason,
        }


class AssetInventory:
    """Live registry of all discovered endpoints, servers, and perimeter devices."""

    def __init__(self):
        self.assets: Dict[str, NetworkAsset] = {}

    def register_or_update(
        self,
        ip: str,
        mac: str = "UNKNOWN",
        hostname: Optional[str] = None,
        port: Optional[int] = None,
    ) -> NetworkAsset:
        now_iso = datetime.now(timezone.utc).isoformat()

        if ip not in self.assets:
            # Automatic role heuristics
            role = "Workstation"
            criticality = "Medium"
            if ip.endswith(".1") or ip.endswith(".254"):
                role = "Gateway"
                criticality = "Critical"

            asset = NetworkAsset(
                ip=ip,
                mac=mac,
                hostname=hostname or f"node-{ip.replace('.', '-')}",
                vendor=self._infer_vendor(mac),
                role=role,
                criticality=criticality,
                first_seen=now_iso,
                last_seen=now_iso,
            )
            self.assets[ip] = asset
        else:
            asset = self.assets[ip]
            asset.last_seen = now_iso
            if mac and mac != "UNKNOWN" and asset.mac == "UNKNOWN":
                asset.mac = mac
                asset.vendor = self._infer_vendor(mac)
            if hostname and asset.hostname.startswith("node-"):
                asset.hostname = hostname

        if port:
            asset.open_ports.add(port)
            self._refine_role(asset, port)

        return asset

    def _refine_role(self, asset: NetworkAsset, port: int) -> None:
        """Dynamically promotes device criticality and role based on exposed services."""
        if port in {3306, 5432, 1433, 1521, 27017}:
            asset.role = "Database"
            asset.criticality = "Critical"
        elif port in {80, 443, 8080, 8443}:
            if asset.role != "Database" and asset.role != "Gateway":
                asset.role = "Web/App Server"
                asset.criticality = "High"
        elif port in {389, 636, 88}:  # LDAP, Kerberos
            asset.role = "Domain Controller"
            asset.criticality = "Critical"
        elif port in {22, 3389, 445}:
            if asset.role == "Workstation":
                asset.role = "Server"
                asset.criticality = "High"

    def _infer_vendor(self, mac: str) -> str:
        prefix = mac[:8].upper()
        vendor_db = {
            "00:0C:29": "VMware Virtual Machine",
            "00:50:56": "VMware ESXi",
            "08:00:27": "Oracle VirtualBox",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Foundation",
            "F0:18:98": "Apple Inc.",
            "3C:22:FB": "Apple Inc.",
            "70:85:C2": "Intel Corporate",
            "B4:2E:99": "Dell Inc.",
        }
        return vendor_db.get(prefix, "Standard Network Interface")

    def get_asset(self, ip: str) -> Optional[NetworkAsset]:
        return self.assets.get(ip)

    def list_assets(self) -> List[Dict]:
        return [asset.to_dict() for asset in self.assets.values()]
