/**
 * NEXUS-SHIELD: Clean Modern SOC Controller
 * Designed for intuitive clarity, zero complexity, and real-time responsiveness.
 * Developed by Amarthaluri Srinivasu
 */

// DOM Elements
const heroBanner = document.getElementById("hero-banner");
const bannerTitle = document.getElementById("banner-title");
const bannerDesc = document.getElementById("banner-desc");
const bannerTag = document.getElementById("banner-tag");
const bannerScore = document.getElementById("banner-score");
const bannerIcon = document.getElementById("banner-icon");

const globalStatusPill = document.getElementById("global-status-pill");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");

const btnSimAttack = document.getElementById("btn-sim-attack");
const btnReset = document.getElementById("btn-reset");
const btnOpenDrawer = document.getElementById("btn-open-drawer");
const btnCloseDrawer = document.getElementById("btn-close-drawer");
const btnDevInfo = document.getElementById("btn-dev-info");
const btnDrawerSim = document.getElementById("btn-drawer-sim");
const drawerOverlay = document.getElementById("drawer-overlay");

const nodePC01 = document.getElementById("node-pc01");
const pc01Badge = document.getElementById("pc01-badge");
const pc01Status = document.getElementById("pc01-status");
const pc01Stamp = document.getElementById("pc01-stamp");

const nodeAppSrv = document.getElementById("node-appsrv");
const appsrvBadge = document.getElementById("appsrv-badge");
const appsrvStatus = document.getElementById("appsrv-status");

const attackPathTracker = document.getElementById("attack-path-tracker");
const defenseLog = document.getElementById("defense-log");

const riskPill = document.getElementById("risk-pill");
const ptsScan = document.getElementById("pts-scan");
const ptsLateral = document.getElementById("pts-lateral");
const ptsDB = document.getElementById("pts-db");
const barScan = document.getElementById("bar-scan");
const barLateral = document.getElementById("bar-lateral");
const barDB = document.getElementById("bar-db");
const riskVerdict = document.getElementById("risk-verdict");

const containmentStatusPill = document.getElementById("containment-status-pill");
const containmentTarget = document.getElementById("containment-target");
const containmentRule = document.getElementById("containment-rule");
const btnToggleQuarantine = document.getElementById("btn-toggle-quarantine");
const toastContainer = document.getElementById("toast-container");

let isUnderAttack = false;
let isQuarantined = false;

// Device Information Database for Clean Click Inspector
const DEVICE_INFO = {
  "192.168.1.1": { name: "GATEWAY-01", role: "Perimeter Router", mac: "00:50:56:01:00:01", ports: "80, 443, 53" },
  "192.168.1.10": { name: "PC-01 (Marketing)", role: "Workstation", mac: "F0:18:98:23:44:11", ports: "445 (SMB), 3389 (RDP)" },
  "192.168.1.15": { name: "PC-02 (Accounting)", role: "Workstation", mac: "3C:22:FB:99:88:77", ports: "Standard HTTP/S" },
  "192.168.1.50": { name: "APP-SRV-01", role: "Application Server", mac: "00:0C:29:AA:BB:CC", ports: "80, 445 (SMB), 8080" },
  "192.168.1.100": { name: "DB-FINANCIAL", role: "Crown Jewel Production DB", mac: "00:50:56:DE:AD:BE", ports: "5432 (PostgreSQL)" }
};

// Add entry to Live Defense Activity Log
function addLogEntry(type, badgeClass, message) {
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0];
  const item = document.createElement("div");
  item.className = "log-item";
  item.innerHTML = `
    <span class="log-time">${timeStr}</span>
    <span class="log-badge ${badgeClass}">${type}</span>
    <span class="log-text">${message}</span>
  `;
  defenseLog.insertBefore(item, defenseLog.firstChild);
}

// Show Toast
function showToast(msg) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerText = msg;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// 1. Attack & Defense Simulation Trigger
function runAttackSimulation() {
  if (isUnderAttack) return;
  isUnderAttack = true;

  btnSimAttack.disabled = true;
  btnSimAttack.innerHTML = `<span>⏳ Simulating...</span>`;

  // Step 1: Reconnaissance (Port Sweep)
  addLogEntry("RECON", "danger", "PC-01 (192.168.1.10) initiated rapid 10-port scan toward App Server.");
  nodePC01.classList.add("compromised");
  pc01Badge.className = "device-badge danger";
  pc01Badge.innerText = "Recon Active";
  pc01Status.className = "device-status-text danger";
  pc01Status.innerText = "Scanning Subnet";

  ptsScan.innerText = "+35 pts";
  barScan.style.width = "70%";
  barScan.className = "r-fill danger";

  bannerScore.innerText = "40";
  bannerScore.className = "metric-big danger";
  riskPill.innerText = "40 / 100";
  riskPill.className = "risk-pill danger";

  // Step 2: Lateral Movement Hop (at 750ms)
  setTimeout(() => {
    addLogEntry("LATERAL", "danger", "PC-01 pivoted to APP-SRV-01 over SMB Port 445 using cached credentials.");
    nodeAppSrv.classList.add("pivot-target");
    appsrvBadge.className = "device-badge danger";
    appsrvBadge.innerText = "SMB Pivot Target";
    appsrvStatus.className = "device-status-text danger";
    appsrvStatus.innerText = "Unauthorized Hop";

    ptsLateral.innerText = "+45 pts";
    barLateral.style.width = "90%";
    barLateral.className = "r-fill danger";

    attackPathTracker.classList.remove("hidden");
    bannerScore.innerText = "85";
    riskPill.innerText = "85 / 100";
  }, 750);

  // Step 3: Attack Path Threatens Database (at 1500ms)
  setTimeout(() => {
    addLogEntry("BLAST RISK", "danger", "Attack path reaches Crown Jewel DB-FINANCIAL (192.168.1.100). Composite risk: 91/100 [CRITICAL].");
    ptsDB.innerText = "+25 pts";
    barDB.style.width = "85%";
    barDB.className = "r-fill danger";

    bannerScore.innerText = "91";
    riskPill.innerText = "91 / 100";
    riskVerdict.innerHTML = `<strong style="color: #F87171;">Critical Alert:</strong> Multi-hop lateral movement detected. Automated containment threshold exceeded.`;

    heroBanner.className = "hero-status-banner compromised";
    bannerIcon.innerHTML = `<span class="banner-icon">🚨</span>`;
    bannerTitle.innerText = "🚨 Threat Detected: PC-01 Isolated";
    bannerDesc.innerText = "PC-01 attempted unauthorized SMB lateral pivot toward Financial Database. Threat score: 91/100. Host contained in 0.4ms.";
    bannerTag.className = "threat-level-tag danger";
    bannerTag.innerText = "THREAT LEVEL: CRITICAL";

    globalStatusPill.className = "system-status-pill danger";
    statusDot.className = "status-dot red";
    statusText.innerText = "THREAT ISOLATED";
  }, 1500);

  // Step 4: Automated Windows Firewall Containment (at 2100ms)
  setTimeout(() => {
    isQuarantined = true;
    pc01Stamp.classList.remove("hidden");
    pc01Badge.innerText = "ISOLATED";
    pc01Status.innerText = "Blocked";

    containmentStatusPill.className = "containment-status-pill isolated";
    containmentStatusPill.innerText = "HOST QUARANTINED";
    containmentTarget.innerHTML = `<strong style="color: #F87171;">192.168.1.10 (PC-01)</strong>`;
    containmentRule.innerText = `netsh advfirewall firewall add rule name="NEXUS-ISOLATE-192.168.1.10" dir=out action=block`;
    btnToggleQuarantine.disabled = false;
    btnToggleQuarantine.innerText = "Release Quarantine";

    addLogEntry("CONTAINMENT", "contain", "NEXUS-SHIELD generated native Windows Firewall isolation rule. Malicious outbound sockets severed.");
    showToast("🚨 Host 192.168.1.10 isolated via native Windows Firewall rule.");

    btnSimAttack.disabled = false;
    btnSimAttack.innerHTML = `<span>⚡ Run Simulation Again</span>`;
  }, 2100);
}

// 2. Reset Network Function
function resetNetwork() {
  isUnderAttack = false;
  isQuarantined = false;

  // Reset Banner
  heroBanner.className = "hero-status-banner secure";
  bannerIcon.innerHTML = `<span class="banner-icon">🛡️</span>`;
  bannerTitle.innerText = "Network Protected: All 5 Devices Safe";
  bannerDesc.innerText = "Continuous in-memory monitoring is active. Lateral movement detectors and zero-trust Windows Firewall containment are armed.";
  bannerTag.className = "threat-level-tag safe";
  bannerTag.innerText = "THREAT LEVEL: LOW";
  bannerScore.innerText = "5";
  bannerScore.className = "metric-big";

  // Reset Global Pill
  globalStatusPill.className = "system-status-pill";
  statusDot.className = "status-dot green";
  statusText.innerText = "NETWORK SECURE";

  // Reset Devices
  nodePC01.className = "device-card normal";
  pc01Badge.className = "device-badge normal";
  pc01Badge.innerText = "Workstation";
  pc01Status.className = "device-status-text safe";
  pc01Status.innerText = "Clean";
  pc01Stamp.classList.add("hidden");

  nodeAppSrv.className = "device-card normal";
  appsrvBadge.className = "device-badge normal";
  appsrvBadge.innerText = "App Server";
  appsrvStatus.className = "device-status-text safe";
  appsrvStatus.innerText = "Clean";

  attackPathTracker.classList.add("hidden");

  // Reset Risk
  riskPill.innerText = "5 / 100";
  riskPill.className = "risk-pill safe";
  ptsScan.innerText = "0 pts";
  ptsLateral.innerText = "0 pts";
  ptsDB.innerText = "0 pts";
  barScan.style.width = "0%";
  barScan.className = "r-fill";
  barLateral.style.width = "0%";
  barLateral.className = "r-fill";
  barDB.style.width = "0%";
  barDB.className = "r-fill";
  riskVerdict.innerHTML = `<strong>Status:</strong> Normal network operations. No containment action needed.`;

  // Reset Containment
  containmentStatusPill.className = "containment-status-pill armed";
  containmentStatusPill.innerText = "ARMED";
  containmentTarget.innerText = "None (All Hosts Clean)";
  containmentRule.innerText = "Waiting for threat trigger";
  btnToggleQuarantine.disabled = true;
  btnToggleQuarantine.innerText = "Release Quarantine";

  btnSimAttack.disabled = false;
  btnSimAttack.innerHTML = `<span>⚡ Simulate Threat & Defend</span>`;

  addLogEntry("RESET", "safe", "Baseline recalibrated. Host quarantine released and firewall rules purged.");
  showToast("🔄 Network reset. All devices returned to safe baseline.");
}

// 3. Toggle Quarantine Manually
btnToggleQuarantine.addEventListener("click", () => {
  if (isQuarantined) {
    // Release
    isQuarantined = false;
    pc01Stamp.classList.add("hidden");
    pc01Badge.innerText = "Workstation";
    pc01Status.innerText = "Monitoring";
    nodePC01.classList.remove("compromised");
    containmentStatusPill.className = "containment-status-pill armed";
    containmentStatusPill.innerText = "ARMED";
    containmentTarget.innerText = "None (Quarantine Released)";
    btnToggleQuarantine.innerText = "Host Unblocked";
    btnToggleQuarantine.disabled = true;
    addLogEntry("RELEASE", "safe", "Administrator released quarantine rule for 192.168.1.10.");
    showToast("✅ Quarantine released. Network traffic resumed.");
  }
});

// Device Click Inspector
document.querySelectorAll(".device-card").forEach(card => {
  card.addEventListener("click", () => {
    const ip = card.getAttribute("data-ip");
    const dev = DEVICE_INFO[ip];
    if (dev) {
      showToast(`💻 ${dev.name} [${ip}] | Role: ${dev.role} | Ports: ${dev.ports}`);
    }
  });
});

// Drawer Open / Close
function openDrawer() { drawerOverlay.classList.add("open"); }
function closeDrawer() { drawerOverlay.classList.remove("open"); }

btnOpenDrawer.addEventListener("click", openDrawer);
btnDevInfo.addEventListener("click", openDrawer);
btnCloseDrawer.addEventListener("click", closeDrawer);
drawerOverlay.addEventListener("click", (e) => {
  if (e.target === drawerOverlay) closeDrawer();
});

btnDrawerSim.addEventListener("click", () => {
  closeDrawer();
  setTimeout(() => runAttackSimulation(), 300);
});

// Buttons
btnSimAttack.addEventListener("click", runAttackSimulation);
btnReset.addEventListener("click", resetNetwork);

// Welcome toast
setTimeout(() => {
  showToast("🛡️ NEXUS-SHIELD Active • Developed by Amarthaluri Srinivasu");
}, 400);
