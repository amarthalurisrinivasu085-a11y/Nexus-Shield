/**
 * NEXUS-SHIELD: Dynamic Frontend Defense Operations Center
 * Controls Canvas Network Security Graph, Live Packet Feeds,
 * Attack Chain Simulator, Risk Scoring, and Automated Containment.
 */

// Initial Network State
const NETWORK_NODES = [
  {
    id: "192.168.1.1",
    label: "GATEWAY-01",
    role: "Perimeter Router",
    criticality: "Critical",
    mac: "00:50:56:01:00:01",
    openPorts: [80, 443, 53],
    status: "NORMAL",
    riskScore: 5,
    x: 450,
    y: 70,
    color: "#06B6D4",
    icon: "🌐",
    blastCount: 0
  },
  {
    id: "192.168.1.10",
    label: "PC-01",
    role: "Workstation (Marketing)",
    criticality: "Medium",
    mac: "F0:18:98:23:44:11",
    openPorts: [445, 3389],
    status: "COMPROMISED",
    riskScore: 91,
    x: 200,
    y: 220,
    color: "#EF4444",
    icon: "💻",
    blastCount: 3
  },
  {
    id: "192.168.1.15",
    label: "PC-02",
    role: "Workstation (Accounting)",
    criticality: "Medium",
    mac: "3C:22:FB:99:88:77",
    openPorts: [],
    status: "NORMAL",
    riskScore: 12,
    x: 700,
    y: 220,
    color: "#06B6D4",
    icon: "💻",
    blastCount: 0
  },
  {
    id: "192.168.1.50",
    label: "APP-SRV-01",
    role: "Internal Application Server",
    criticality: "High",
    mac: "00:0C:29:AA:BB:CC",
    openPorts: [80, 445, 8080],
    status: "SUSPICIOUS",
    riskScore: 68,
    x: 350,
    y: 380,
    color: "#F59E0B",
    icon: "🖥️",
    blastCount: 2
  },
  {
    id: "192.168.1.100",
    label: "DB-FINANCIAL",
    role: "Production Database",
    criticality: "Critical",
    mac: "00:50:56:DE:AD:BE",
    openPorts: [5432],
    status: "TARGETED",
    riskScore: 85,
    x: 550,
    y: 440,
    color: "#8B5CF6",
    icon: "🗄️",
    blastCount: 1
  }
];

// Graph Edges (Traffic Flows)
let NETWORK_EDGES = [
  { source: "192.168.1.10", target: "192.168.1.1", protocol: "HTTPS", port: 443, type: "normal" },
  { source: "192.168.1.15", target: "192.168.1.1", protocol: "DNS", port: 53, type: "normal" },
  { source: "192.168.1.50", target: "192.168.1.100", protocol: "PGSQL", port: 5432, type: "normal" },
  { source: "192.168.1.10", target: "192.168.1.50", protocol: "SMB", port: 445, type: "attack" },
  { source: "192.168.1.50", target: "192.168.1.100", protocol: "SQL-QUERY", port: 5432, type: "attack" }
];

// Active Particles for Edge Animation
let particles = [];

// DOM Elements
const canvas = document.getElementById("networkGraphCanvas");
const ctx = canvas.getContext("2d");
const packetLogTerminal = document.getElementById("packet-log-terminal");
const assetTableBody = document.getElementById("asset-table-body");
const btnSimulate = document.getElementById("btn-simulate-attack");
const btnReset = document.getElementById("btn-reset-baseline");
const btnExport = document.getElementById("btn-export-report");
const btnTriggerQuarantine = document.getElementById("btn-trigger-quarantine");
const btnReleaseQuarantine = document.getElementById("btn-release-quarantine");
const toastContainer = document.getElementById("toast-container");

let selectedNode = NETWORK_NODES[1]; // PC-01 default
let isQuarantined = false;

// ============================================================================
// Canvas Graph Rendering Engine
// ============================================================================

function initCanvas() {
  function resize() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }
  resize();
  window.addEventListener("resize", resize);

  // Spawn flowing particles
  for (let i = 0; i < 20; i++) {
    particles.push({
      edgeIndex: Math.floor(Math.random() * NETWORK_EDGES.length),
      progress: Math.random(),
      speed: 0.004 + Math.random() * 0.005
    });
  }

  // Handle click on canvas
  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    for (let node of NETWORK_NODES) {
      const dist = Math.hypot(clickX - node.x, clickY - node.y);
      if (dist < 28) {
        selectNode(node);
        break;
      }
    }
  });

  requestAnimationFrame(renderGraph);
}

function renderGraph() {
  const rect = canvas.getBoundingClientRect();
  ctx.clearRect(0, 0, rect.width, rect.height);

  // 1. Draw Edges
  NETWORK_EDGES.forEach((edge, idx) => {
    const src = NETWORK_NODES.find(n => n.id === edge.source);
    const dst = NETWORK_NODES.find(n => n.id === edge.target);
    if (!src || !dst) return;

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(dst.x, dst.y);

    if (edge.type === "attack") {
      if (isQuarantined && (edge.source === "192.168.1.10" || edge.target === "192.168.1.10")) {
        // Severed link
        ctx.strokeStyle = "rgba(100, 116, 139, 0.4)";
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 6]);
      } else {
        // Active Attack Edge
        ctx.strokeStyle = "rgba(239, 68, 68, 0.85)";
        ctx.lineWidth = 3;
        ctx.setLineDash([6, 6]);
        ctx.shadowColor = "#EF4444";
        ctx.shadowBlur = 12;
      }
    } else {
      ctx.strokeStyle = "rgba(6, 182, 212, 0.25)";
      ctx.lineWidth = 1.5;
    }
    ctx.stroke();
    ctx.restore();

    // Draw protocol pill on edge
    const midX = (src.x + dst.x) / 2;
    const midY = (src.y + dst.y) / 2;
    ctx.fillStyle = edge.type === "attack" ? "rgba(239, 68, 68, 0.9)" : "rgba(14, 21, 38, 0.85)";
    ctx.fillRect(midX - 22, midY - 9, 44, 18);
    ctx.strokeStyle = edge.type === "attack" ? "#EF4444" : "rgba(6, 182, 212, 0.4)";
    ctx.strokeRect(midX - 22, midY - 9, 44, 18);
    ctx.fillStyle = "#FFFFFF";
    ctx.font = "9px 'JetBrains Mono'";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(`${edge.protocol}`, midX, midY);
  });

  // 2. Animate Traffic Particles
  if (!isQuarantined) {
    particles.forEach(p => {
      const edge = NETWORK_EDGES[p.edgeIndex];
      if (!edge) return;
      const src = NETWORK_NODES.find(n => n.id === edge.source);
      const dst = NETWORK_NODES.find(n => n.id === edge.target);
      if (!src || !dst) return;

      p.progress += p.speed;
      if (p.progress > 1) p.progress = 0;

      const px = src.x + (dst.x - src.x) * p.progress;
      const py = src.y + (dst.y - src.y) * p.progress;

      ctx.save();
      ctx.beginPath();
      ctx.arc(px, py, edge.type === "attack" ? 4 : 3, 0, Math.PI * 2);
      ctx.fillStyle = edge.type === "attack" ? "#F87171" : "#38BDF8";
      ctx.shadowColor = edge.type === "attack" ? "#EF4444" : "#06B6D4";
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.restore();
    });
  }

  // 3. Draw Nodes
  NETWORK_NODES.forEach(node => {
    ctx.save();

    // Pulse ring for compromised or high risk
    if (node.status === "COMPROMISED" && !isQuarantined) {
      const time = Date.now() * 0.003;
      const pulseSize = 26 + Math.sin(time) * 6;
      ctx.beginPath();
      ctx.arc(node.x, node.y, pulseSize, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(239, 68, 68, 0.5)";
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Node outer circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);

    if (node.status === "QUARANTINED") {
      ctx.fillStyle = "#1E293B";
      ctx.strokeStyle = "#64748B";
    } else if (node.status === "COMPROMISED") {
      ctx.fillStyle = "rgba(239, 68, 68, 0.25)";
      ctx.strokeStyle = "#EF4444";
      ctx.shadowColor = "#EF4444";
      ctx.shadowBlur = 15;
    } else if (node.status === "TARGETED") {
      ctx.fillStyle = "rgba(139, 92, 246, 0.25)";
      ctx.strokeStyle = "#8B5CF6";
      ctx.shadowColor = "#8B5CF6";
      ctx.shadowBlur = 12;
    } else {
      ctx.fillStyle = "rgba(6, 182, 212, 0.15)";
      ctx.strokeStyle = "#06B6D4";
    }

    ctx.lineWidth = selectedNode.id === node.id ? 3.5 : 2;
    ctx.fill();
    ctx.stroke();

    // Draw Icon
    ctx.font = "16px sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(node.icon, node.x, node.y);

    // Draw Label & IP below
    ctx.fillStyle = "#F8FAFC";
    ctx.font = "bold 11px 'Inter'";
    ctx.fillText(node.label, node.x, node.y + 36);

    ctx.fillStyle = node.status === "COMPROMISED" ? "#F87171" : "#94A3B8";
    ctx.font = "10px 'JetBrains Mono'";
    ctx.fillText(node.id, node.x, node.y + 49);

    ctx.restore();
  });

  requestAnimationFrame(renderGraph);
}

// ============================================================================
// Node Inspection & UI Updates
// ============================================================================

function selectNode(node) {
  selectedNode = node;
  document.getElementById("inspect-node-title").textContent = `Selected Node: ${node.label} (${node.id})`;
  const badge = document.getElementById("inspect-node-badge");
  badge.textContent = node.status;
  badge.className = `badge ${node.status === 'COMPROMISED' ? 'badge-danger' : 'badge-outline'}`;

  document.getElementById("inspect-role").textContent = node.role;
  document.getElementById("inspect-mac").textContent = node.mac;
  document.getElementById("inspect-ports").textContent = node.openPorts.length > 0 ? node.openPorts.join(", ") : "None Detected";
  document.getElementById("inspect-blast").textContent = `${node.blastCount} Critical Assets in Blast Radius`;
}

// ============================================================================
// Live Packet Streaming Log Generator
// ============================================================================

const SAMPLE_LOGS = [
  { proto: "TCP", src: "192.168.1.10", dst: "192.168.1.50:445", text: "[SYN_SENT] Anomalous SMB session probe", cls: "proto-smb", alert: true },
  { proto: "DNS", src: "192.168.1.15", dst: "192.168.1.1:53", text: "QUERY A cdn.microsoft.com [Normal]", cls: "proto-dns", alert: false },
  { proto: "TCP", src: "192.168.1.10", dst: "192.168.1.50:3389", text: "[SYN] RDP port sweep attempt", cls: "proto-smb", alert: true },
  { proto: "ARP", src: "00:50:56:01:00:01", dst: "FF:FF:FF:FF:FF:FF", text: "Who has 192.168.1.100? Tell 192.168.1.1", cls: "proto-arp", alert: false },
  { proto: "TCP", src: "192.168.1.50", dst: "192.168.1.100:5432", text: "PostgreSQL Handshake Seq=1023", cls: "proto-tcp", alert: false },
  { proto: "SMB", src: "192.168.1.10", dst: "192.168.1.50", text: "Tree Connect: IPC$ - Admin Token Asserted", cls: "proto-smb", alert: true }
];

let logCounter = 0;

function streamPackets() {
  setInterval(() => {
    const item = SAMPLE_LOGS[logCounter % SAMPLE_LOGS.length];
    logCounter++;

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    const logDiv = document.createElement("div");
    logDiv.className = "log-line";
    logDiv.innerHTML = `
      <span class="log-time">[${timeStr}]</span>
      <span class="log-proto ${item.cls}">${item.proto}</span>
      <span class="log-src">${item.src}</span>
      <span class="log-arrow">➔</span>
      <span class="log-dst">${item.dst}</span>
      <span class="${item.alert ? 'log-alert' : 'log-text'}">${item.text}</span>
    `;

    packetLogTerminal.appendChild(logDiv);
    if (packetLogTerminal.children.length > 50) {
      packetLogTerminal.removeChild(packetLogTerminal.firstChild);
    }
    packetLogTerminal.scrollTop = packetLogTerminal.scrollHeight;
  }, 1200);
}

// ============================================================================
// Asset Table Rendering
// ============================================================================

function renderAssetTable() {
  assetTableBody.innerHTML = "";
  NETWORK_NODES.forEach(node => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono"><strong>${node.id}</strong></td>
      <td>${node.label}</td>
      <td>${node.role}</td>
      <td><span class="badge ${node.criticality === 'Critical' ? 'badge-danger' : 'badge-outline'}">${node.criticality}</span></td>
      <td class="mono ${node.riskScore > 75 ? 'danger-text' : ''}"><strong>${node.riskScore}/100</strong></td>
      <td><span class="status-tag ${node.status.toLowerCase()}">${node.status}</span></td>
      <td>
        ${node.status === 'COMPROMISED' ? 
          `<button class="btn btn-danger btn-sm" onclick="triggerQuarantine('${node.id}')">Quarantine</button>` : 
          node.status === 'QUARANTINED' ? 
          `<button class="btn btn-outline btn-sm" onclick="releaseQuarantine('${node.id}')">Restore</button>` : 
          `<span style="color:var(--text-muted)">Protected</span>`
        }
      </td>
    `;
    assetTableBody.appendChild(tr);
  });
}

// ============================================================================
// Automated Containment Handlers
// ============================================================================

function triggerQuarantine(ip = "192.168.1.10") {
  isQuarantined = true;
  const node = NETWORK_NODES.find(n => n.id === ip);
  if (node) {
    node.status = "QUARANTINED";
    node.riskScore = 0;
  }

  document.getElementById("containment-engine-status").textContent = "QUARANTINE EXECUTED";
  document.getElementById("containment-engine-status").className = "metric-value danger-text";
  document.getElementById("containment-badge").textContent = "ISOLATED";
  document.getElementById("containment-badge").style.background = "rgba(239, 68, 68, 0.25)";
  document.getElementById("btn-trigger-quarantine").classList.add("hidden");
  document.getElementById("btn-release-quarantine").classList.remove("hidden");
  document.getElementById("global-risk-value").textContent = "18 / 100";
  document.getElementById("global-risk-badge").textContent = "CONTAINED";
  document.getElementById("global-risk-badge").className = "severity-pill";
  document.getElementById("defcon-value").textContent = "LEVEL 5 (NORMAL)";
  document.getElementById("defcon-value").className = "metric-value active-green";

  showToast(`🛡️ Host ${ip} successfully isolated via dynamic firewall rule: NEXUS_ISOLATE_${ip.replace(/\./g, '_')}`);
  renderAssetTable();
  selectNode(node);
}

function releaseQuarantine(ip = "192.168.1.10") {
  isQuarantined = false;
  const node = NETWORK_NODES.find(n => n.id === ip);
  if (node) {
    node.status = "COMPROMISED";
    node.riskScore = 91;
  }

  document.getElementById("containment-engine-status").textContent = "ARMED & ACTIVE";
  document.getElementById("containment-engine-status").className = "metric-value active-green";
  document.getElementById("containment-badge").textContent = "ARMED";
  document.getElementById("containment-badge").style.background = "rgba(16, 185, 129, 0.2)";
  document.getElementById("btn-trigger-quarantine").classList.remove("hidden");
  document.getElementById("btn-release-quarantine").classList.add("hidden");
  document.getElementById("global-risk-value").textContent = "91 / 100";
  document.getElementById("global-risk-badge").textContent = "CRITICAL";
  document.getElementById("global-risk-badge").className = "severity-pill critical";
  document.getElementById("defcon-value").textContent = "LEVEL 2 (ELEVATED)";
  document.getElementById("defcon-value").className = "metric-value danger-text";

  showToast(`✅ Quarantine removed for ${ip}. Restored network routing.`);
  renderAssetTable();
  selectNode(node);
}

window.triggerQuarantine = triggerQuarantine;
window.releaseQuarantine = releaseQuarantine;

btnTriggerQuarantine.addEventListener("click", () => triggerQuarantine("192.168.1.10"));
btnReleaseQuarantine.addEventListener("click", () => releaseQuarantine("192.168.1.10"));

// Simulate Attack Chain
btnSimulate.addEventListener("click", () => {
  showToast("⚡ Initiating Automated Multi-Stage Attack Simulation...");
  setTimeout(() => {
    showToast("🚨 STAGE 1: Vertical Port Reconnaissance detected from 192.168.1.10 hitting ports 21, 22, 80, 445, 3389!");
  }, 1000);
  setTimeout(() => {
    showToast("🚨 STAGE 2: Lateral Movement pivot over SMB (Port 445) targeting APP-SRV-01 (192.168.1.50)!");
  }, 2500);
  setTimeout(() => {
    showToast("🚨 STAGE 3: Crown Jewel Exposure! Blast radius reaching DB-FINANCIAL (192.168.1.100)!");
    if (!isQuarantined) {
      triggerQuarantine("192.168.1.10");
    }
  }, 4200);
});

// Reset Baseline
btnReset.addEventListener("click", () => {
  releaseQuarantine("192.168.1.10");
  showToast("🔄 Behavioral baseline and rolling traffic counters recalibrated.");
});

// Export Incident Log
btnExport.addEventListener("click", () => {
  const incidentData = {
    platform: "NEXUS-SHIELD",
    version: "2.6.4",
    exportTime: new Date().toISOString(),
    globalRiskIndex: 91,
    severity: "CRITICAL",
    compromisedHost: "192.168.1.10",
    attackChain: ["192.168.1.10", "192.168.1.50", "192.168.1.100"],
    blastRadius: {
      criticalAssetsReachable: ["192.168.1.100 (DB-FINANCIAL)", "192.168.1.50 (APP-SRV-01)"],
      score: 85
    },
    containmentStatus: isQuarantined ? "ISOLATED" : "PENDING_ACTION",
    networkNodes: NETWORK_NODES,
    activeEdges: NETWORK_EDGES
  };

  const blob = new Blob([JSON.stringify(incidentData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `NEXUS-SHIELD-INCIDENT-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("📥 Incident report exported successfully as JSON.");
});

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<span>${message}</span>`;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Initial Setup
initCanvas();
streamPackets();
renderAssetTable();
selectNode(selectedNode);
