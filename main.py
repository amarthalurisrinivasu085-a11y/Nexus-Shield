"""
NEXUS-SHIELD: CLI Runner & Live Defense Simulation
Demonstrates full cycle of threat detection:
Asset Discovery -> Flow Tracking -> Port Scan Detection -> Lateral Movement -> Risk Scoring -> Automated Quarantine.
"""

import sys
import io

# Ensure UTF-8 output encoding for Windows terminals (PowerShell / Command Prompt)
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import time
import json
from core.flow_tracker import FlowTracker
from discovery.asset_inventory import AssetInventory
from detector.port_scan import PortScanDetector
from detector.lateral_movement import LateralMovementDetector
from graph.network_graph import NetworkSecurityGraph
from engine.risk_scorer import RiskScorer
from containment.quarantine import QuarantineController

# Top-level FastAPI instance for Vercel / serverless deployments
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, FileResponse
    import os

    app = FastAPI(title="NEXUS-SHIELD", version="2.6.4")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    @app.get("/", response_class=HTMLResponse)
    def read_root():
        index_path = os.path.join(BASE_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>NEXUS-SHIELD SOC Dashboard Active</h1>"

    @app.get("/index.css")
    def get_css():
        path = os.path.join(BASE_DIR, "index.css")
        if os.path.exists(path):
            return FileResponse(path, media_type="text/css")
        return ""

    @app.get("/app.js")
    def get_js():
        path = os.path.join(BASE_DIR, "app.js")
        if os.path.exists(path):
            return FileResponse(path, media_type="application/javascript")
        return ""

    @app.get("/api/health")
    def health():
        return {
            "status": "online",
            "platform": "NEXUS-SHIELD",
            "developer": "Amarthaluri Srinivasu",
            "version": "2.6.4"
        }
except Exception:
    app = None


def run_demonstration():
    print("=" * 80)
    print("🛡️  NEXUS-SHIELD: REAL-TIME ADAPTIVE NETWORK THREAT DETECTION & CONTAINMENT")
    print("=" * 80)

    # Initialize engines
    inventory = AssetInventory()
    flow_tracker = FlowTracker()
    scan_detector = PortScanDetector()
    lateral_detector = LateralMovementDetector()
    graph = NetworkSecurityGraph()
    scorer = RiskScorer()
    quarantine = QuarantineController(dry_run=True)

    # Seed baseline assets
    print("\n[+] Initializing Network Asset Baseline...")
    assets = [
        ("192.168.1.1", "00:50:56:01:00:01", "gateway.corp.local", 80),
        ("192.168.1.10", "F0:18:98:23:44:11", "pc-01-marketing", None),
        ("192.168.1.15", "3C:22:FB:99:88:77", "pc-02-accounting", None),
        ("192.168.1.50", "00:0C:29:AA:BB:CC", "app-srv-01", 445),
        ("192.168.1.100", "00:50:56:DE:AD:BE", "db-prod-financial", 5432),
    ]

    for ip, mac, host, port in assets:
        asset = inventory.register_or_update(ip, mac, host, port)
        graph.upsert_node(
            node_id=ip,
            role=asset.role,
            criticality=asset.criticality,
            risk_score=asset.risk_score,
            open_ports=list(asset.open_ports),
        )
        print(f"    - Discovered: {asset.ip:15} | Role: {asset.role:15} | Criticality: {asset.criticality}")

    # Establish normal background baseline traffic
    print("\n[+] Modeling Normal Traffic Baseline...")
    graph.add_flow_edge("192.168.1.10", "192.168.1.1", "TCP", 443, packets=42, bytes_transferred=38400)
    graph.add_flow_edge("192.168.1.50", "192.168.1.100", "TCP", 5432, packets=120, bytes_transferred=182000)

    # Scenario Step 1: Initial Compromise & Internal Reconnaissance (Port Sweep)
    compromised_ip = "192.168.1.10"
    print(f"\n[!] ATTACK SIMULATION STAGE 1: Reconnaissance initiated from {compromised_ip}...")
    scan_alert = None
    scanned_ports = [21, 22, 23, 25, 80, 135, 443, 445, 3389, 8080]
    for p in scanned_ports:
        scan_alert = scan_detector.record_attempt(compromised_ip, "192.168.1.50", p)
        time.sleep(0.02)

    if scan_alert:
        print(f"    🚨 DETECTED: {scan_alert.alert_type}")
        print(f"       Summary: {scan_alert.summary}")

    # Scenario Step 2: Lateral Movement Pivot
    print(f"\n[!] ATTACK SIMULATION STAGE 2: Lateral Movement Pivot ({compromised_ip} -> 192.168.1.50:445 SMB)...")
    lat_alert = lateral_detector.record_connection(compromised_ip, "192.168.1.50", 445)
    graph.add_flow_edge(compromised_ip, "192.168.1.50", "TCP", 445, packets=18, bytes_transferred=14200, is_anomalous=True)

    if lat_alert:
        print(f"    🚨 DETECTED: Lateral Pivot over {lat_alert.protocol_name}")
        print(f"       Chain: {' -> '.join(lat_alert.hop_chain)}")

    # Scenario Step 3: Attack Path & Blast Radius Calculation
    print("\n[+] Computing Attack Graph & Blast Radius...")
    blast = graph.calculate_blast_radius(compromised_ip)
    print(f"    Compromised Node: {compromised_ip}")
    print(f"    Total Reachable Assets: {blast['total_reachable_count']}")
    for target in blast["critical_targets_at_risk"]:
        print(f"    ⚠️  Crown Jewel at Risk: {target['target_ip']} ({target['role']}) via Path: {' -> '.join(target['path'])}")

    # Scenario Step 4: Composite Risk Scoring
    signals = ["VERTICAL_PORT_SCAN", "LATERAL_MOVEMENT_PEER"]
    risk = scorer.evaluate(
        source_ip=compromised_ip,
        detected_signals=signals,
        target_criticality="High",
        blast_score=blast["blast_score"],
    )

    print("\n[+] NEXUS-SHIELD RISK ENGINE EVALUATION:")
    print(f"    Source IP: {risk.source_ip}")
    print(f"    Composite Threat Score: {risk.composite_score}/100 [{risk.severity}]")
    print("    Contributing Factors:")
    for f in risk.contributing_factors:
        print(f"      • {f}")
    print(f"    Recommended Defense Action: {risk.recommended_action}")

    # Scenario Step 5: Automated Containment Trigger
    if risk.severity in {"HIGH", "CRITICAL"}:
        print("\n[🚨] EXECUTING AUTOMATED CONTAINMENT PROTOCOL...")
        containment_rec = quarantine.isolate_host(
            compromised_ip,
            reason=f"High-confidence lateral movement & reconnaissance (Risk {risk.composite_score}/100)"
        )
        print(f"    ✓ Host {compromised_ip} ISOLATED.")
        print(f"    ✓ Firewall Rule: {containment_rec.rule_name}")
        print(f"    ✓ Generated Command: {containment_rec.firewall_command}")
        print(f"    ✓ Containment State: ACTIVE")

    print("\n" + "=" * 80)
    print("✅ NEXUS-SHIELD SIMULATION CYCLE COMPLETE.")
    print("=" * 80)


if __name__ == "__main__":
    run_demonstration()
