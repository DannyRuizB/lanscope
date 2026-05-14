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
const notifier = require("./notifier");

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

// v0.11.0 — notification channel validators.

const ALLOWED_EVENTS = new Set([
  "scan_done",
  "scan_error",
  "scan_skipped",
  "baseline_diff", // v0.13.0
]);
const ALLOWED_CHANNEL_TYPES = new Set(["webhook", "ntfy"]);
const ALLOWED_WEBHOOK_FORMATS = new Set(["generic", "discord", "slack"]);

function validateChannelName(s) {
  if (typeof s !== "string") return { error: "name is required" };
  const v = s.trim();
  if (v.length === 0) return { error: "name cannot be empty" };
  if (v.length > 80) return { error: "name too long (max 80 chars)" };
  return { value: v };
}

function validateChannelType(s) {
  if (!ALLOWED_CHANNEL_TYPES.has(s)) {
    return { error: `type must be one of: ${Array.from(ALLOWED_CHANNEL_TYPES).join(", ")}` };
  }
  return { value: s };
}

function validateHttpUrl(s) {
  if (typeof s !== "string") return null;
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return s;
  } catch {
    return null;
  }
}

function validateChannelConfig(type, config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return { error: "config is required" };
  }
  if (type === "webhook") {
    if (!validateHttpUrl(config.url)) {
      return { error: "config.url must be a valid http(s) URL" };
    }
    const format = config.format == null ? "generic" : config.format;
    if (!ALLOWED_WEBHOOK_FORMATS.has(format)) {
      return {
        error: `config.format must be one of: ${Array.from(ALLOWED_WEBHOOK_FORMATS).join(", ")}`,
      };
    }
    return { value: { url: config.url, format } };
  }
  if (type === "ntfy") {
    if (typeof config.topic !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(config.topic)) {
      return { error: "config.topic must be 1..64 chars (letters, digits, _ or -)" };
    }
    const server = config.server == null ? "https://ntfy.sh" : validateHttpUrl(config.server);
    if (!server) return { error: "config.server must be a valid http(s) URL" };
    return { value: { topic: config.topic, server } };
  }
  return { error: "unknown type" };
}

function validateChannelEvents(events) {
  if (!Array.isArray(events)) return { error: "events must be an array" };
  if (events.length === 0) return { error: "events cannot be empty" };
  const bad = events.find((e) => typeof e !== "string" || !ALLOWED_EVENTS.has(e));
  if (bad) {
    return {
      error: `event not allowed: ${bad}. Use one of: ${Array.from(ALLOWED_EVENTS).join(", ")}`,
    };
  }
  // dedupe preserving order
  const seen = new Set();
  const out = [];
  for (const e of events) {
    if (!seen.has(e)) {
      seen.add(e);
      out.push(e);
    }
  }
  return { value: out };
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

// v0.12.0 — per-CIDR timeline: aggregated metrics across scans in a time window.
const TIMELINE_RANGES = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

app.get("/api/timeline", (req, res) => {
  const { cidr, range } = req.query || {};
  const cidrErr = validateCidr(cidr);
  if (cidrErr) return res.status(400).json({ error: cidrErr });

  let fromTs = 0;
  if (range && range !== "all") {
    const span = TIMELINE_RANGES[range];
    if (!span) return res.status(400).json({ error: "invalid range, use 24h|7d|30d|all" });
    fromTs = Date.now() - span;
  }
  res.json(db.getTimeline(cidr, fromTs));
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

// v0.11.0 — notification channels. The /test endpoint lives in the next
// step (needs the notifier module to actually dispatch).

app.get("/api/notifications", (req, res) => {
  res.json({ channels: db.listChannels() });
});

app.post("/api/notifications", (req, res) => {
  const body = req.body || {};

  const nameV = validateChannelName(body.name);
  if (nameV.error) return res.status(400).json({ error: nameV.error });

  const typeV = validateChannelType(body.type);
  if (typeV.error) return res.status(400).json({ error: typeV.error });

  const cfgV = validateChannelConfig(typeV.value, body.config);
  if (cfgV.error) return res.status(400).json({ error: cfgV.error });

  const evtV = validateChannelEvents(body.events);
  if (evtV.error) return res.status(400).json({ error: evtV.error });

  const channel = db.createChannel({
    name: nameV.value,
    type: typeV.value,
    config: cfgV.value,
    events: evtV.value,
    enabled: body.enabled !== false,
  });
  res.status(201).json({ channel });
});

app.patch("/api/notifications/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const current = db.getChannel(id);
  if (!current) return res.status(404).json({ error: "channel not found" });

  const body = req.body || {};
  const patch = {};

  // Channel type is immutable — recreate the channel if you need to switch
  // between webhook and ntfy (config shape is incompatible).
  if (Object.prototype.hasOwnProperty.call(body, "type") && body.type !== current.type) {
    return res
      .status(400)
      .json({ error: "channel type is immutable. Delete and recreate the channel." });
  }

  if (Object.prototype.hasOwnProperty.call(body, "name")) {
    const v = validateChannelName(body.name);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.name = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "config")) {
    const v = validateChannelConfig(current.type, body.config);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.config = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "events")) {
    const v = validateChannelEvents(body.events);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.events = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "enabled")) {
    if (typeof body.enabled !== "boolean") {
      return res.status(400).json({ error: "enabled must be boolean" });
    }
    patch.enabled = body.enabled;
  }

  const channel = db.updateChannel(id, patch);
  res.json({ channel });
});

app.delete("/api/notifications/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  if (!db.deleteChannel(id)) return res.status(404).json({ error: "channel not found" });
  res.status(204).end();
});

// Fires a synthetic scan_done payload against the channel and awaits the
// response so the UI can show the downstream success/failure inline.
app.post("/api/notifications/:id/test", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const channel = db.getChannel(id);
  if (!channel) return res.status(404).json({ error: "channel not found" });

  const testContext = {
    schedule: { id: 0, name: `${channel.name} (test)`, cidr: "192.168.1.0/24" },
    scan: { id: 0, host_count: 12, started_at: Date.now() },
    error: null,
  };

  try {
    await notifier.sendToChannel(channel, "scan_done", testContext);
    db.recordChannelDispatch(id, { status: "done" });
    res.json({ ok: true, channel: db.getChannel(id) });
  } catch (e) {
    db.recordChannelDispatch(id, { status: "error", error: e.message });
    res.status(502).json({ error: e.message, channel: db.getChannel(id) });
  }
});

// v0.13.0 — alerts: baseline-divergence events emitted after each scan.

const ALERT_TYPES_SET = new Set(db.ALERT_TYPES);

function parseCidrQuery(raw) {
  if (raw === undefined || raw === null || raw === "") return { value: null };
  if (typeof raw !== "string" || raw.length > 32) return { error: "invalid cidr" };
  return { value: raw };
}

function parseAlertTypesQuery(raw) {
  if (raw === undefined || raw === null || raw === "") return { value: null };
  const parts = String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return { value: null };
  for (const t of parts) {
    if (!ALERT_TYPES_SET.has(t)) return { error: `unknown alert type: ${t}` };
  }
  return { value: parts };
}

app.get("/api/alerts", (req, res) => {
  const cidrV = parseCidrQuery(req.query.cidr);
  if (cidrV.error) return res.status(400).json({ error: cidrV.error });
  const typesV = parseAlertTypesQuery(req.query.types);
  if (typesV.error) return res.status(400).json({ error: typesV.error });

  const filters = {};
  if (cidrV.value) filters.cidr = cidrV.value;
  if (req.query.unackOnly === "true") filters.unackOnly = true;
  if (typesV.value) filters.types = typesV.value;
  if (req.query.limit !== undefined) {
    const n = parseInt(req.query.limit, 10);
    if (!Number.isInteger(n) || n <= 0 || n > 1000) {
      return res.status(400).json({ error: "limit must be an integer 1..1000" });
    }
    filters.limit = n;
  }
  res.json({ alerts: db.listAlerts(filters) });
});

app.get("/api/alerts/count", (req, res) => {
  const cidrV = parseCidrQuery(req.query.cidr);
  if (cidrV.error) return res.status(400).json({ error: cidrV.error });
  const opts = {};
  if (cidrV.value) opts.cidr = cidrV.value;
  res.json({ count: db.countUnackedAlerts(opts) });
});

app.post("/api/alerts/:id/ack", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const before = db.getAlert(id);
  if (!before) return res.status(404).json({ error: "alert not found" });
  const alert = db.ackAlert(id);
  res.json({ alert });
});

app.delete("/api/alerts/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  if (!db.deleteAlert(id)) return res.status(404).json({ error: "alert not found" });
  res.status(204).end();
});

app.listen(PORT, () => {
  console.log(`LanScope listening on http://0.0.0.0:${PORT}`);
  scheduler.init();
});
