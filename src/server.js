const path = require("node:path");
const express = require("express");
const db = require("./db");
const {
  validateCidr,
  validateIpv4,
  validateTiming,
  validatePortsSpec,
  validateScanType,
  validateScripts,
  validateDiscovery,
  runPortScan,
  runUdpPortScan,
  runOsScan,
} = require("./scanner");
const {
  validateScheduleName,
  validateKeepLast,
  validateLatencyAlertMs,
  validateCronExpr,
  validateChannelName,
  validateChannelType,
  validateChannelConfig,
  validateChannelEvents,
  validateLabelText,
  validateNotesText,
} = require("./http-validators");
const {
  scanToCsv, exportFilename, historyToCsv, historyFilename, alertsToCsv, alertsFilename,
} = require("./export");
const { sendWake } = require("./wol");
const { executeCidrScan } = require("./runner");
const { detectSensitivePortsForHost } = require("./alerts");
const scheduler = require("./scheduler");
const notifier = require("./notifier");
const { basicAuth } = require("./auth");

const PORT = parseInt(process.env.PORT, 10) || 3030;
const DEMO_MODE = process.env.DEMO_MODE === "true";

// Optional HTTP Basic Auth (v1.6.0): both variables or neither. A
// half-configured lock silently left open is the worst outcome, so refuse
// to start rather than guess what the operator meant.
const AUTH_USER = process.env.AUTH_USER || "";
const AUTH_PASS = process.env.AUTH_PASS || "";
if ((AUTH_USER === "") !== (AUTH_PASS === "")) {
  console.error("[auth] AUTH_USER and AUTH_PASS must be set together — refusing to start half-configured.");
  process.exit(1);
}

if (DEMO_MODE) {
  try {
    require("./seed").run();
  } catch (e) {
    console.error("[demo] seed failed:", e);
  }
}

const app = express();
app.use(express.json({ limit: "32kb" }));

// Auth sits ABOVE the static files on purpose: the UI itself is the
// inventory of your network — there is nothing here worth serving to an
// unauthenticated visitor.
if (AUTH_USER) {
  app.use(basicAuth({ user: AUTH_USER, pass: AUTH_PASS }));
  console.log("[auth] HTTP Basic Auth enabled");
}

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

// v1.1.0 — export a scan as a file. GET on purpose: it works in the
// read-only public demo too, and the browser can download it with a plain
// anchor click (no fetch/blob dance).
app.get("/api/scans/:id/export", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const format = req.query.format || "csv";
  if (format !== "csv" && format !== "json") {
    return res.status(400).json({ error: "invalid format, use csv|json" });
  }
  const scan = db.getScan(id);
  if (!scan) return res.status(404).json({ error: "scan not found" });

  res.setHeader("Content-Disposition", `attachment; filename="${exportFilename(scan, format)}"`);
  if (format === "json") return res.json(scan);
  const labelsByIp = Object.fromEntries(
    db.listLabels(scan.cidr).filter((l) => l.label).map((l) => [l.ip, l.label])
  );
  res.type("text/csv; charset=utf-8").send(scanToCsv(scan, labelsByIp));
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

// v1.7.0 — one host across every scan of its CIDR (the UI's drill-down
// modal). A GET on purpose, like export: it works on the read-only demo.
app.get("/api/host-history", (req, res) => {
  const { cidr, ip } = req.query || {};
  const cidrErr = validateCidr(cidr);
  if (cidrErr) return res.status(400).json({ error: cidrErr });
  const ipErr = validateIpv4(ip);
  if (ipErr) return res.status(400).json({ error: ipErr });
  res.json(db.getHostHistory(cidr, ip));
});

// v1.10.0 — download a host's history as CSV / JSON, mirroring the scan
// export. GET on purpose: the ⬇ button in the history modal is a plain
// anchor, and it works on the read-only demo.
app.get("/api/host-history/export", (req, res) => {
  const { cidr, ip } = req.query || {};
  const cidrErr = validateCidr(cidr);
  if (cidrErr) return res.status(400).json({ error: cidrErr });
  const ipErr = validateIpv4(ip);
  if (ipErr) return res.status(400).json({ error: ipErr });
  const format = req.query.format || "csv";
  if (format !== "csv" && format !== "json") {
    return res.status(400).json({ error: "invalid format, use csv|json" });
  }
  const history = db.getHostHistory(cidr, ip);
  res.setHeader("Content-Disposition", `attachment; filename="${historyFilename(history, format)}"`);
  if (format === "json") return res.json(history);
  res.type("text/csv; charset=utf-8").send(historyToCsv(history));
});

// v1.9.0 — every host's latency series over the last scans of a network, in
// one call (the sparkline column needs all rows at once). A GET on purpose:
// it also works on the read-only public demo.
app.get("/api/latency-sparks", (req, res) => {
  const { cidr } = req.query || {};
  const err = validateCidr(cidr);
  if (err) return res.status(400).json({ error: err });
  res.json(db.getLatencySparks(cidr));
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
    // v1.18.0 — the watchlist is checked HERE, right after the ports land:
    // a discovery sweep only pings, so this is the first moment anything
    // knows which ports a host exposes. Never lets a detector or webhook
    // failure spoil a successful port scan.
    let exposure = [];
    try {
      exposure = detectSensitivePortsForHost(id);
    } catch (e) {
      console.error(`[alerts] sensitive-port detect failed for host ${id}: ${e.message}`);
    }
    if (exposure.length > 0) {
      const p = exposure[0].payload || {};
      notifier
        .dispatch("sensitive_port", {
          scan: { id: refreshed.scan_id, cidr: db.getScan(refreshed.scan_id)?.cidr ?? null },
          total: exposure.length,
          watchlist: p.watchlist ?? null,
          exposed_hosts: [{ ip: p.ip ?? null, hostname: p.hostname ?? null, ports: p.ports || [] }],
        })
        .catch((e) => console.error(`[server] dispatch sensitive_port failed: ${e.message}`));
    }
    res.json({
      host_id: id,
      ip: host.ip,
      portscanned_at: refreshed.portscanned_at,
      ports: saved.ports,
      host_scripts: saved.host_scripts,
      sensitive_port_alerts: exposure.length,
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

// v1.2.0 — Wake-on-LAN. Unlike the scan endpoints this does NOT require the
// host to be up: waking a sleeping/disappeared device is the whole point. It
// does require a MAC — the magic packet is addressed to the NIC, not the IP.
app.post("/api/hosts/:id/wake", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const host = db.getHost(id);
  if (!host) return res.status(404).json({ error: "host not found" });
  if (!host.mac) {
    return res.status(400).json({ error: "host has no MAC address — Wake-on-LAN needs one" });
  }

  try {
    const result = await sendWake(host.mac);
    res.json({ host_id: id, ip: host.ip, mac: host.mac, sent: true, ...result });
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

// v1.3.0 — host labels: user-assigned friendly name + notes, keyed by
// (cidr, ip) so they follow the device across every scan of that network.
app.get("/api/labels", (req, res) => {
  const cidr = req.query.cidr;
  const errorMsg = validateCidr(cidr);
  if (errorMsg) return res.status(400).json({ error: errorMsg });
  res.json({ labels: db.listLabels(cidr) });
});

// PUT (idempotent upsert) on purpose: the UI has exactly one form per
// (cidr, ip) and saving it twice must not create two rows. Sending both
// fields empty clears the label entirely.
app.put("/api/labels", (req, res) => {
  const { cidr, ip } = req.body || {};
  const cidrError = validateCidr(cidr);
  if (cidrError) return res.status(400).json({ error: cidrError });
  const ipError = validateIpv4(ip);
  if (ipError) return res.status(400).json({ error: ipError });
  const label = validateLabelText(req.body.label);
  if (label.error) return res.status(400).json({ error: label.error });
  const notes = validateNotesText(req.body.notes);
  if (notes.error) return res.status(400).json({ error: notes.error });
  const row = db.upsertLabel({ cidr, ip, label: label.value, notes: notes.value });
  res.json({ label: row }); // null when the upsert cleared it
});

// v1.20.0 — per-host alert mutes. Same (cidr, ip) keying and PUT-upsert
// shape as labels: the UI has exactly one toggle per host and flipping it
// twice must not create two rows. `muted` is a strict boolean on purpose —
// a truthy string like "false" silently muting a host would be the worst
// kind of bug to chase.
app.get("/api/mutes", (req, res) => {
  const cidr = req.query.cidr;
  const errorMsg = validateCidr(cidr);
  if (errorMsg) return res.status(400).json({ error: errorMsg });
  res.json({ mutes: db.listMutes(cidr) });
});

app.put("/api/mutes", (req, res) => {
  const { cidr, ip, muted, types, until } = req.body || {};
  const cidrError = validateCidr(cidr);
  if (cidrError) return res.status(400).json({ error: cidrError });
  const ipError = validateIpv4(ip);
  if (ipError) return res.status(400).json({ error: ipError });
  if (typeof muted !== "boolean") {
    return res.status(400).json({ error: "muted must be true or false" });
  }
  // v1.21.0 — optional scope. Omitted/null mutes every type (the v1.20
  // shape, still the UI's "mute everything"). An array mutes just those
  // types; an empty array is rejected — a mute of nothing is an unmute,
  // and accepting it would store a row that silences nothing but still
  // wears the 🔕. A full set is canonicalized to null so "everything"
  // has exactly one spelling in the table.
  let scope = null;
  if (types !== undefined && types !== null) {
    if (!Array.isArray(types) || types.length === 0) {
      return res
        .status(400)
        .json({ error: "types must be a non-empty array of alert types (or omitted to mute all)" });
    }
    const unique = [...new Set(types)];
    for (const t of unique) {
      if (!ALERT_TYPES_SET.has(t)) {
        return res.status(400).json({ error: `unknown alert type: ${t}` });
      }
    }
    scope = unique.length === db.ALERT_TYPES.length ? null : unique;
  }
  // v1.22.0 — optional snooze. Omitted/null mutes forever (the v1.20/21
  // shape); an epoch-ms `until` arms the mute only until then. Absolute on
  // purpose — the UI's "keep current deadline" round-trips exactly, and the
  // stored row is returned verbatim. Must sit in the future (small client
  // clock skew shortens a snooze, it never rejects one) and within a year:
  // beyond that you mean "forever", and "forever" has one spelling — null.
  let expiresAt = null;
  if (until !== undefined && until !== null) {
    if (!Number.isInteger(until)) {
      return res
        .status(400)
        .json({ error: "until must be an epoch-ms integer (or omitted to mute forever)" });
    }
    const now = Date.now();
    if (until <= now) {
      return res.status(400).json({ error: "until must be in the future" });
    }
    if (until > now + 366 * 24 * 3600 * 1000) {
      return res.status(400).json({ error: "until is more than a year away — omit it to mute forever" });
    }
    expiresAt = until;
  }
  const row = muted ? db.setMute(cidr, ip, scope, expiresAt) : db.clearMute(cidr, ip);
  res.json({ mute: row }); // null when the mute was cleared
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

  const keepV = validateKeepLast(body.keep_last);
  if (keepV.error) return res.status(400).json({ error: keepV.error });

  const latencyV = validateLatencyAlertMs(body.latency_alert_ms);
  if (latencyV.error) return res.status(400).json({ error: latencyV.error });

  const schedule = db.createSchedule({
    name: nameV.value,
    cidr: body.cidr,
    cron_expr: cronV.value,
    enabled: body.enabled !== false,
    scan_options: body.scan_options || null,
    keep_last: keepV.value,
    latency_alert_ms: latencyV.value,
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
  if (Object.prototype.hasOwnProperty.call(body, "keep_last")) {
    const v = validateKeepLast(body.keep_last);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.keep_last = v.value;
  }
  if (Object.prototype.hasOwnProperty.call(body, "latency_alert_ms")) {
    const v = validateLatencyAlertMs(body.latency_alert_ms);
    if (v.error) return res.status(400).json({ error: v.error });
    patch.latency_alert_ms = v.value;
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

// v1.16.0 — fire the daily digest on demand instead of waiting for the
// DIGEST_CRON tick. Same code path as the cron (scheduler.runDigest), so a
// channel subscribed to daily_digest gets exactly what it would at 8am. The
// DEMO_MODE middleware above already 403s this (POST), and the notifier
// short-circuits in demo anyway.
app.post("/api/digest/run", async (req, res) => {
  try {
    const dispatch = await scheduler.runDigest();
    res.json({ ok: true, dispatch });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
  const err = validateCidr(raw);
  if (err) return { error: err };
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

// v1.19.0 — export the alert list, completing the export trio (scans v1.1.0,
// host history v1.10.0, alerts here). A GET like the other two, so it works on
// the read-only public demo, and it takes the SAME filters as /api/alerts:
// what you exported is what the sidebar was showing, filter chips included —
// an export that silently ignored the active filter would be worse than none.
// No `limit` on purpose: a report is the whole set, not a page of it.
app.get("/api/alerts/export", (req, res) => {
  const cidrV = parseCidrQuery(req.query.cidr);
  if (cidrV.error) return res.status(400).json({ error: cidrV.error });
  const typesV = parseAlertTypesQuery(req.query.types);
  if (typesV.error) return res.status(400).json({ error: typesV.error });
  const format = req.query.format || "csv";
  if (format !== "csv" && format !== "json") {
    return res.status(400).json({ error: "invalid format, use csv|json" });
  }
  const filters = {};
  if (cidrV.value) filters.cidr = cidrV.value;
  if (req.query.unackOnly === "true") filters.unackOnly = true;
  if (typesV.value) filters.types = typesV.value;
  const alerts = db.listAlerts(filters);
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${alertsFilename(filters, format)}"`,
  );
  if (format === "json") {
    return res.json({ filters, count: alerts.length, alerts });
  }
  res.type("text/csv; charset=utf-8").send(alertsToCsv(alerts));
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
