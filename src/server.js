const path = require("node:path");
const express = require("express");
const cron = require("node-cron");
const db = require("./db");
const {
  validateCidr,
  validateTiming,
  validatePortsSpec,
  validateScanType,
  validateScripts,
  validateDiscovery,
  runPortScan,
  runUdpPortScan,
  runOsScan,
} = require("./scanner");
const { executeCidrScan } = require("./runner");
const scheduler = require("./scheduler");

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

// v0.10.0 — validators that only the HTTP layer cares about. The scan
// executor and option validator live in runner.js / scheduler.js.

function validateScheduleName(s) {
  if (typeof s !== "string") return { error: "name is required" };
  const name = s.trim();
  if (name.length === 0) return { error: "name cannot be empty" };
  if (name.length > 80) return { error: "name too long (max 80 chars)" };
  return { value: name };
}

function validateCronExpr(s) {
  if (typeof s !== "string" || s.trim().length === 0) {
    return { error: "cron_expr is required" };
  }
  const expr = s.trim();
  if (!cron.validate(expr)) return { error: "invalid cron expression" };
  return { value: expr };
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

  const result = await executeCidrScan(cidr, { discoveryArgs: discovery.args });
  if (result.busy) {
    return res.status(409).json({ error: "another scan is already in progress" });
  }
  if (result.error) {
    return res.status(500).json({ error: result.error, scan_id: result.scanId });
  }
  res.json(result.scan);
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

// v0.10.0 — scheduled scans. Persistence + REST surface. The actual cron
// timer lives in src/scheduler.js (next step) and reloads on every mutation.

app.get("/api/schedules", (req, res) => {
  res.json({ schedules: db.listSchedules() });
});

app.post("/api/schedules", (req, res) => {
  const body = req.body || {};

  const cidrErr = validateCidr(body.cidr);
  if (cidrErr) return res.status(400).json({ error: cidrErr });

  const nameV = validateScheduleName(body.name);
  if (nameV.error) return res.status(400).json({ error: nameV.error });

  const cronV = validateCronExpr(body.cron_expr);
  if (cronV.error) return res.status(400).json({ error: cronV.error });

  const optsV = scheduler.validateScheduleScanOptions(body.scan_options);
  if (optsV.error) return res.status(400).json({ error: optsV.error });

  const schedule = db.createSchedule({
    name: nameV.value,
    cidr: body.cidr,
    cron_expr: cronV.value,
    enabled: body.enabled !== false,
    scan_options: body.scan_options || null,
  });
  scheduler.reload();
  res.status(201).json({ schedule });
});

app.patch("/api/schedules/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  if (!db.getSchedule(id)) return res.status(404).json({ error: "schedule not found" });

  const body = req.body || {};
  const patch = {};

  if (Object.prototype.hasOwnProperty.call(body, "name")) {
    const v = validateScheduleName(body.name);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.name = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "cidr")) {
    const err = validateCidr(body.cidr);
    if (err) return res.status(400).json({ error: err });
    patch.cidr = body.cidr;
  }
  if (Object.prototype.hasOwnProperty.call(body, "cron_expr")) {
    const v = validateCronExpr(body.cron_expr);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.cron_expr = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "enabled")) {
    if (typeof body.enabled !== "boolean") {
      return res.status(400).json({ error: "enabled must be boolean" });
    }
    patch.enabled = body.enabled;
  }
  if (Object.prototype.hasOwnProperty.call(body, "scan_options")) {
    const v = scheduler.validateScheduleScanOptions(body.scan_options);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.scan_options = body.scan_options;
  }

  const schedule = db.updateSchedule(id, patch);
  scheduler.reload();
  res.json({ schedule });
});

app.delete("/api/schedules/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  if (!db.deleteSchedule(id)) return res.status(404).json({ error: "schedule not found" });
  scheduler.reload();
  res.status(204).end();
});

// Manual trigger that takes the same code path as a cron tick — same
// validation, same lock, same persistence of last_run_* fields.
app.post("/api/schedules/:id/run-now", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const schedule = db.getSchedule(id);
  if (!schedule) return res.status(404).json({ error: "schedule not found" });

  const result = await scheduler.runScheduled(schedule);
  const updated = db.getSchedule(id);

  if (result.status === "skipped") {
    return res.status(409).json({ error: result.error, schedule: updated });
  }
  if (result.status === "error") {
    return res
      .status(500)
      .json({ error: result.error, scan_id: result.scanId || null, schedule: updated });
  }
  res.json({ scan_id: result.scanId, scan: result.scan, schedule: updated });
});

app.listen(PORT, () => {
  console.log(`LanScope listening on http://0.0.0.0:${PORT}`);
  scheduler.init();
});
