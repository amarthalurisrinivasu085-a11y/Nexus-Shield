from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="NEXUS-SHIELD API",
    description="Adaptive Network Threat Detection & Automated Containment Platform",
    version="2.6.4"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "platform": "NEXUS-SHIELD",
        "version": "2.6.4",
        "developer": "Amarthaluri Srinivasu",
        "defense_engine": "ACTIVE"
    }

@app.get("/api/status")
def status():
    return {
        "threat_level": "LOW",
        "defcon": "LEVEL 2",
        "risk_index": 5,
        "containment": "ARMED",
        "monitored_hosts": 5
    }

@app.get("/api/simulate")
def simulate():
    return {
        "compromised_host": "192.168.1.10",
        "threat_type": "VERTICAL_SCAN_AND_SMB_PIVOT",
        "risk_score": 91,
        "severity": "CRITICAL",
        "firewall_rule": 'netsh advfirewall firewall add rule name="NEXUS-ISOLATE-192.168.1.10" dir=out action=block',
        "latency_ms": 0.4
    }
