const path = require("node:path");
const express = require("express");
const db = require("./db");
const {
  validateCidr,
  validateTiming,
  validatePortsSpec,
  validateScanType,
  validateScripts,
  validateDiscovery,
  runPingSweep,
  runPortScan,
  runUdpPortScan,
  runOsScan,
} = require("./scanner");

const PORT = parseInt(process.env.PORT, 10) || 3030;
const DEMO_MODE = process.env.DEMO_MODE === "true";

if (DEMO_MODE) {
  try {
    require("./seed").run();
  } catch (e) {
    console.error("[demo] seed failed:", e);
  }
}

const app = express();
app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Demo mode (v0.9.0): the public demo deploy serves pre-seeded fixtures and
// must not run nmap (would scan the data centre's network — illegal and
// useless to the visitor). Block every state-changing request with 403.
if (DEMO_MODE) {
  app.use((req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    res.status(403).json({
      error: "Demo mode: this LanScope instance is read-only. Install it locally to run real scans.",
      demoMode: true,
    });
  });
}

app.get("/api/config", (req, res) => {
  res.json({ demoMode: DEMO_MODE });
});

app.get("/api/scans", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  res.json({ scans: db.listScans(limit) });
});

app.get("/api/scans/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const scan = db.getScan(id);
  if (!scan) return res.status(404).json({ error: "scan not found" });
  res.json(scan);
});

app.delete("/api/scans/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const ok = db.deleteScan(id);
  if (!ok) return res.status(404).json({ error: "scan not found" });
  res.status(204).end();
});

app.post("/api/scan", async (req, res) => {
  const { cidr } = req.body || {};
  const error = validateCidr(cidr);
  if (error) return res.status(400).json({ error });

  const discovery = validateDiscovery(req.body?.discovery);
  if (discovery.error) return res.status(400).json({ error: discovery.error });

  const scanId = db.startScan(cidr);
  try {
    const hosts = await runPingSweep(cidr, { discoveryArgs: discovery.args });
    db.finishScan(scanId, hosts);
    res.json(db.getScan(scanId));
  } catch (e) {
    db.failScan(scanId, e.message);
    res.status(500).json({ error: e.message, scan_id: scanId });
  }
});

app.post("/api/hosts/:id/portscan", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const host = db.getHost(id);
  if (!host) return res.status(404).json({ error: "host not found" });
  if (host.status !== "up") return res.status(400).json({ error: "host is not up" });

  const timing = validateTiming(req.body?.timing);
  if (timing.error) return res.status(400).json({ error: timing.error });

  const portsSpec = validatePortsSpec(req.body?.ports);
  if (portsSpec.error) return res.status(400).json({ error: portsSpec.error });

  const scanType = validateScanType(req.body?.scanType);
  if (scanType.error) return res.status(400).json({ error: scanType.error });

  const scripts = validateScripts(req.body?.scripts);
  if (scripts.error) return res.status(400).json({ error: scripts.error });

  try {
    const result = await runPortScan(host.ip, {
      timing: timing.value,
      portsArgs: portsSpec.args,
      scanType: scanType.value,
      scriptsArgs: scripts.args,
    });
    const saved = db.saveHostPorts(id, result.ports, result.host_scripts);
    const refreshed = db.getHost(id);
    res.json({
      host_id: id,
      ip: host.ip,
      portscanned_at: refreshed.portscanned_at,
      ports: saved.ports,
      host_scripts: saved.host_scripts,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/hosts/:id/udp-portscan", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const host = db.getHost(id);
  if (!host) return res.status(404).json({ error: "host not found" });
  if (host.status !== "up") return res.status(400).json({ error: "host is not up" });

  const timing = validateTiming(req.body?.timing);
  if (timing.error) return res.status(400).json({ error: timing.error });

  const portsSpec = validatePortsSpec(req.body?.ports);
  if (portsSpec.error) return res.status(400).json({ error: portsSpec.error });

  try {
    const ports = await runUdpPortScan(host.ip, {
      timing: timing.value,
      portsArgs: portsSpec.args,
    });
    const saved = db.saveHostUdpPorts(id, ports);
    const refreshed = db.getHost(id);
    res.json({
      host_id: id,
      ip: host.ip,
      udp_portscanned_at: refreshed.udp_portscanned_at,
      udp_ports: saved,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/hosts/:id/osscan", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const host = db.getHost(id);
  if (!host) return res.status(404).json({ error: "host not found" });
  if (host.status !== "up") return res.status(400).json({ error: "host is not up" });

  try {
    const matches = await runOsScan(host.ip);
    const saved = db.saveHostOsMatches(id, matches);
    const refreshed = db.getHost(id);
    res.json({
      host_id: id,
      ip: host.ip,
      osscanned_at: refreshed.osscanned_at,
      os_matches: saved,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// v0.8.0 — inventory baselines: at most one per CIDR.
app.get("/api/inventory", (req, res) => {
  res.json({ baselines: db.listBaselines() });
});

app.post("/api/inventory", (req, res) => {
  const scanId = parseInt(req.body?.scan_id, 10);
  if (!Number.isInteger(scanId) || scanId <= 0) {
    return res.status(400).json({ error: "scan_id is required" });
  }
  const scan = db.getScan(scanId);
  if (!scan) return res.status(404).json({ error: "scan not found" });
  if (scan.status !== "done") {
    return res.status(400).json({ error: "scan must be completed to become a baseline" });
  }
  const baseline = db.setBaseline(scanId);
  res.json({ baseline });
});

app.delete("/api/inventory/:cidr", (req, res) => {
  const cidr = req.params.cidr;
  const errorMsg = validateCidr(cidr);
  if (errorMsg) return res.status(400).json({ error: errorMsg });
  const ok = db.clearBaselineByCidr(cidr);
  if (!ok) return res.status(404).json({ error: "no baseline for this CIDR" });
  res.status(204).end();
});

app.listen(PORT, () => {
  console.log(`LanScope listening on http://0.0.0.0:${PORT}`);
});
