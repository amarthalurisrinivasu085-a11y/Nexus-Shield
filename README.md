# NEXUS-SHIELD
## Real-Time Adaptive Network Threat Detection, Attack-Path Analysis & Automated Containment Platform

---

### 🛡️ Vision & Architecture Overview
**NEXUS-SHIELD** is an enterprise-grade, student-built network security platform designed for real-time defense against modern 2026 attack vectors: vulnerability exploitation, credential abuse, stealthy lateral movement, and data exfiltration.

Instead of operating as a traditional signature-based IDS or a static port scanner, NEXUS-SHIELD constructs an in-memory **Dynamic Network Security Graph** $G = (V, E)$ where:
- **Nodes ($V$)**: Network assets (endpoints, servers, gateways, databases) enriched with role, criticality, and real-time risk scores.
- **Edges ($E$)**: Directional communication channels labeled with protocols, ports, connection frequencies, and byte transfers.
- **Weights ($W$)**: Historical behavioral baselines and anomaly deviations.

```
                    INTERNET / EXTERNAL
                            │
                            ▼
                  ┌──────────────────┐
                  │ ROUTER / GATEWAY │
                  └─────────┬────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
      [ WORKSTATION-01 ] [ WORKSTATION-02 ] [ DMZ-SERVER ]
          │
          │ (Unusual SMB / RDP / Port 445 Pivot)
          ▼
      [ INTERNAL-SRV-01 ]
          │
          │ (Lateral Movement Hop)
          ▼
      [ SENSITIVE-DATABASE ] ──> 🚨 CRITICAL BLAST RADIUS TRIGGER
```

---

### 📦 Modular Platform Architecture

```
nexus-shield/
├── config/
│   └── settings.yaml            # Monitored subnets, risk thresholds, containment mode
├── core/
│   ├── __init__.py
│   ├── capture.py               # Raw socket / Scapy asynchronous packet listener
│   ├── parser.py                # L2 (Ethernet/ARP), L3 (IPv4/IPv6), L4 (TCP/UDP/ICMP), L7 decoders
│   └── flow_tracker.py          # Bidirectional flow & connection state manager
├── discovery/
│   ├── __init__.py
│   ├── asset_inventory.py       # Live asset table (IP, MAC, Hostname, OS/Vendor fingerprint)
│   └── active_probe.py          # Controlled ARP/ICMP & port discovery
├── baseline/
│   ├── __init__.py
│   ├── host_profile.py          # Normal operating profile (usual peers, ports, time windows)
│   └── anomaly_engine.py        # Statistical & threshold deviation scoring
├── detector/
│   ├── __init__.py
│   ├── port_scan.py             # Horizontal (sweep) & vertical (syn/stealth) scan detection
│   ├── lateral_movement.py      # Multi-hop pivot detection (SMB, RDP, WMI, SSH)
│   ├── dns_threats.py           # DGA, DNS tunneling, high-frequency query detection
│   └── exfiltration.py          # Spike & ratio-based outbound data exfiltration detection
├── graph/
│   ├── __init__.py
│   ├── network_graph.py         # NetworkX / in-memory graph representation of live topology
│   └── attack_path.py           # Shortest-path & high-risk critical asset blast-radius calculator
├── engine/
│   ├── __init__.py
│   ├── risk_scorer.py           # Composite risk score calculator (0-100 scale)
│   └── alert_manager.py         # Structured security alerts with mitigation context
├── containment/
│   ├── __init__.py
│   └── quarantine.py            # Windows Firewall rules / Null-routing / Lab safe isolation
├── api/
│   ├── __init__.py
│   ├── server.py                # FastAPI REST & WebSocket streaming server
│   └── routes/                  # API endpoints for assets, flows, alerts, graph, and actions
└── main.py                      # Main entrypoint / CLI controller
```

---

### 🎯 Key Defense Capabilities
1. **Passive & Active Asset Discovery**: Instant mapping of devices, MAC manufacturers, open ports, and device roles.
2. **Behavioral Profiling**: Learns peer-to-peer norms so sudden outbound admin traffic (e.g. PC to PC over 445/3389) immediately raises flags.
3. **Attack Path Graphing**: Visualizes reachable high-value targets (e.g., Domain Controller or Database) from any compromised workstation.
4. **Adaptive Risk Engine**: Normalizes multiple weak signals (new port + sweep + off-hours) into a high-confidence threat score.
5. **Lab-Safe Automated Containment**: Immediate host isolation using native OS firewall rules or packet-level blackholing.
