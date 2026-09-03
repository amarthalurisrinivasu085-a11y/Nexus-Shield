from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
import os

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

# Resolve project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_file(filename: str):
    candidates = [
        os.path.join(BASE_DIR, filename),
        os.path.join(".", filename),
        os.path.join("..", filename),
        filename
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.isfile(c):
            return c
    return None

@app.get("/", response_class=HTMLResponse)
def read_root():
    path = find_file("index.html")
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>NEXUS-SHIELD SOC Dashboard Active</h1>"

@app.get("/index.css")
def get_css():
    path = find_file("index.css")
    if path:
        return FileResponse(path, media_type="text/css")
    return ""

@app.get("/app.js")
def get_js():
    path = find_file("app.js")
    if path:
        return FileResponse(path, media_type="application/javascript")
    return ""

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
