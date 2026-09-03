"""
NEXUS-SHIELD: Adaptive Automated Containment Controller
Implements lab-safe automated host quarantine, dynamic firewall rules,
and isolation commands.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import platform
import subprocess
from typing import Dict, List, Optional


@dataclass
class QuarantineRecord:
    ip: str
    reason: str
    timestamp: str
    rule_name: str
    firewall_command: str
    is_active: bool


class QuarantineController:
    """Safely executes or simulates network containment of compromised hosts."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.active_quarantines: Dict[str, QuarantineRecord] = {}

    def isolate_host(self, ip: str, reason: str) -> QuarantineRecord:
        now_iso = datetime.now(timezone.utc).isoformat()
        rule_name = f"NEXUS_ISOLATE_{ip.replace('.', '_')}"

        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        else:
            cmd = f"iptables -I INPUT -s {ip} -j DROP"

        if not self.dry_run:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except Exception as e:
                pass

        record = QuarantineRecord(
            ip=ip,
            reason=reason,
            timestamp=now_iso,
            rule_name=rule_name,
            firewall_command=cmd,
            is_active=True,
        )
        self.active_quarantines[ip] = record
        return record

    def release_host(self, ip: str) -> bool:
        if ip not in self.active_quarantines:
            return False

        record = self.active_quarantines[ip]
        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = f'netsh advfirewall firewall delete rule name="{record.rule_name}"'
        else:
            cmd = f"iptables -D INPUT -s {ip} -j DROP"

        if not self.dry_run:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except Exception:
                pass

        record.is_active = False
        del self.active_quarantines[ip]
        return True

    def get_quarantined_hosts(self) -> List[Dict]:
        return [
            {
                "ip": r.ip,
                "reason": r.reason,
                "timestamp": r.timestamp,
                "rule_name": r.rule_name,
                "command": r.firewall_command,
                "is_active": r.is_active,
            }
            for r in self.active_quarantines.values()
        ]
