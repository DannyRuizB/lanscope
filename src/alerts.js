// Match between hosts is by IP — MACs can change (renumbering, spoofing,
// virtual MACs) and hostnames may be missing, so IP is the only stable key.
//
// `changed_os` compares OS *buckets* (windows/linux/apple/other), not the raw
// top match name, because nmap's accuracy/order fluctuates between runs even
// when the underlying OS family hasn't changed.

const db = require("./db");

function osBucket(host) {
  if (!host.osscanned_at) return null;
  const top = (host.os_matches || [])[0];
  if (!top) return null;
  const f = (top.family || "").toLowerCase();
  if (f.includes("windows")) return "windows";
  if (f.includes("linux")) return "linux";
  if (f.includes("mac") || f.includes("ios") || f.includes("apple")) return "apple";
  return "other";
}

function tcpOpenPortSet(host) {
  if (!host.portscanned_at) return null;
  const set = new Set();
  for (const p of host.ports || []) {
    if ((p.protocol || "tcp") === "tcp" && p.state === "open") set.add(p.port);
  }
  return set;
}

function normMac(m) {
  const v = (m || "").trim().toLowerCase();
  return v || null;
}

function normName(s) {
  const v = (s || "").trim().toLowerCase();
  return v || null;
}

// v1.12.0 — latency threshold. LATENCY_ALERT_MS is a global knob (unset =
// feature off, the default): when a scan times a host at or above the
// threshold, a high_latency alert fires. Parsed on every call so tests can
// flip it; strict parse — zero, negatives and garbage mean "off" rather than
// a threshold that accidentally matches everything.
function latencyThresholdMs() {
  const raw = (process.env.LATENCY_ALERT_MS || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// v1.17.0 — alert retention. ALERT_RETENTION_DAYS is opt-in like the other
// knobs (unset = keep everything forever, the previous behaviour): acked
// alerts age out N days after they were acknowledged. Same strict parse as
// latencyThresholdMs — zero, negatives and garbage mean "off", never a
// retention window that silently swallows the whole history.
function alertRetentionDays() {
  const raw = (process.env.ALERT_RETENTION_DAYS || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// v1.18.0 — sensitive ports. SENSITIVE_PORTS is an opt-in list (unset =
// feature off, the default): any host found with one of these TCP ports OPEN
// raises a sensitive_port alert. Same strict parse discipline as the latency
// knob — non-numeric or out-of-range entries are dropped rather than silently
// widening or narrowing the watchlist, and an all-garbage list means "off".
function sensitivePorts() {
  const raw = (process.env.SENSITIVE_PORTS || "").trim();
  if (!raw) return null;
  const ports = [];
  for (const part of raw.split(",")) {
    const n = Number(part.trim());
    if (Number.isInteger(n) && n >= 1 && n <= 65535 && !ports.includes(n)) ports.push(n);
  }
  return ports.length ? ports.sort((a, b) => a - b) : null;
}

// v1.14.0 — the threshold a given scan is judged against. A scheduled
// scan's own latency_alert_ms wins over the global env: null inherits,
// 0 means "explicitly off for this schedule" (the WiFi-heavy subnet stops
// paging without silencing everyone else), N > 0 is its own bar. Manual
// scans have no schedule and always use the env.
function effectiveLatencyThreshold(scan) {
  if (scan && scan.schedule_id != null) {
    const schedule = db.getSchedule(scan.schedule_id);
    if (schedule && schedule.latency_alert_ms != null) {
      return schedule.latency_alert_ms > 0 ? schedule.latency_alert_ms : null;
    }
  }
  return latencyThresholdMs();
}

// Unlike the drift detectors below, high latency is a statement about the
// CURRENT scan's health, not about divergence from a declared inventory —
// so it deliberately needs no baseline and fires on any done scan.
function pushLatencySpecs(scan, specs, spec) {
  const threshold = effectiveLatencyThreshold(scan);
  if (threshold === null) return;
  for (const h of scan.hosts || []) {
    if (h.status !== "up") continue;
    if (h.latency_ms == null) continue; // not timed is not "slow"
    if (h.latency_ms < threshold) continue;
    specs.push(
      spec("high_latency", h.id, {
        ip: h.ip,
        hostname: h.hostname || null,
        latency_ms: h.latency_ms,
        threshold_ms: threshold,
      }),
    );
  }
}

// v1.18.0 — the watched ports a host actually EXPOSES. Only `open` counts:
// closed/filtered are exactly what you want to see, and a host nobody
// port-scanned says nothing about its ports (the same "not measured" honesty
// rule latency follows). TCP only, deliberately: the watchlist names TCP
// services (telnet, SMB, RDP), and the UDP scan is a separate, rarely-run
// action.
function openWatchedPorts(ports, watch) {
  return (ports || [])
    .filter((p) => p.state === "open" && watch.includes(p.port))
    .map((p) => ({ port: p.port, service: p.service || null }))
    .sort((a, b) => a.port - b.port);
}

// v1.18.0 — like high_latency, sensitive_port is a statement about the
// CURRENT scan (what a device exposes, not how it drifted), so it needs no
// baseline. On a live sweep this pass is a quiet no-op — discovery only
// pings, so no ports are recorded yet — but hosts that DO carry ports at
// detection time (the seed's fixtures, a scan re-judged after port scans)
// are held to the same watchlist the live path uses.
//
// ONE alert per host listing every watched port found open on it (not one per
// port): the finding is "this device exposes telnet AND SMB", and a box with
// five watched ports open shouldn't drown the sidebar.
function pushSensitivePortSpecs(scan, specs, spec) {
  const watch = sensitivePorts();
  if (watch === null) return;
  for (const h of scan.hosts || []) {
    if (h.status !== "up") continue;
    const open = openWatchedPorts(h.ports, watch);
    if (!open.length) continue;
    specs.push(
      spec("sensitive_port", h.id, {
        ip: h.ip,
        hostname: h.hostname || null,
        ports: open,
        watchlist: watch,
      }),
    );
  }
}

// v1.18.0 — the LIVE hook: a sweep only pings, so in the real flow ports
// arrive per host through POST /api/hosts/:id/portscan, long after the
// scan-level detectors ran. The endpoint calls this the moment the ports
// land — same watchlist, same one-alert-per-host shape as the scan pass.
//
// Re-scanning a host does not pile up duplicates: if that host already has an
// UNACKNOWLEDGED sensitive_port alert for this scan, the finding is already in
// the tray. An acknowledged one does not block a fresh alert — you triaged the
// old exposure, this is news again.
function detectSensitivePortsForHost(hostId) {
  const watch = sensitivePorts();
  if (watch === null) return [];
  const host = db.getHost(hostId);
  if (!host || host.status !== "up") return [];
  const open = openWatchedPorts(db.listTcpPortsByHost(hostId), watch);
  if (!open.length) return [];
  if (db.hasPendingAlertForHost(host.scan_id, hostId, "sensitive_port")) return [];
  return db.createAlerts([
    {
      scan_id: host.scan_id,
      host_id: hostId,
      cidr: db.getScan(host.scan_id)?.cidr,
      type: "sensitive_port",
      payload: {
        ip: host.ip,
        hostname: host.hostname || null,
        ports: open,
        watchlist: watch,
      },
    },
  ]);
}

// Wrap callers in try/catch — a detection failure should never break the
// scan flow. Returns [] when the scan isn't done. The baseline-drift
// detectors additionally need a declared baseline that isn't this very scan
// (self-compare); high_latency and sensitive_port run regardless.
function detectAlertsForScan(scanId) {
  const scan = db.getScan(scanId);
  if (!scan || scan.status !== "done") return [];

  const specs = [];
  const spec = (type, host_id, payload) => ({
    scan_id: scanId,
    host_id,
    cidr: scan.cidr,
    type,
    payload,
  });

  pushLatencySpecs(scan, specs, spec);
  pushSensitivePortSpecs(scan, specs, spec);

  const baseline = db.getBaselineByCidr(scan.cidr);
  if (!baseline || baseline.scan_id === scanId) {
    return specs.length ? db.createAlerts(specs) : [];
  }

  const baselineScan = db.getScan(baseline.scan_id);
  if (!baselineScan) {
    return specs.length ? db.createAlerts(specs) : [];
  }

  const currentByIp = new Map();
  for (const h of scan.hosts || []) {
    if (h.status === "up") currentByIp.set(h.ip, h);
  }
  const baselineByIp = new Map();
  for (const h of baselineScan.hosts || []) {
    if (h.status === "up") baselineByIp.set(h.ip, h);
  }

  for (const [ip, h] of currentByIp) {
    if (baselineByIp.has(ip)) continue;
    specs.push(
      spec("appeared", h.id, {
        ip,
        mac: h.mac || null,
        hostname: h.hostname || null,
        vendor: h.vendor || null,
      }),
    );
  }

  for (const [ip, b] of baselineByIp) {
    if (currentByIp.has(ip)) continue;
    specs.push(
      spec("disappeared", null, {
        ip,
        last_seen_mac: b.mac || null,
        last_seen_hostname: b.hostname || null,
        last_seen_vendor: b.vendor || null,
      }),
    );
  }

  for (const [ip, current] of currentByIp) {
    const base = baselineByIp.get(ip);
    if (!base) continue;

    const cm = normMac(current.mac);
    const bm = normMac(base.mac);
    if (cm && bm && cm !== bm) {
      specs.push(spec("changed_mac", current.id, { ip, before: base.mac, after: current.mac }));
    }

    const ch = normName(current.hostname);
    const bh = normName(base.hostname);
    if (ch && bh && ch !== bh) {
      specs.push(
        spec("changed_hostname", current.id, {
          ip,
          before: base.hostname,
          after: current.hostname,
        }),
      );
    }

    const cob = osBucket(current);
    const bob = osBucket(base);
    if (cob && bob && cob !== bob) {
      specs.push(spec("changed_os", current.id, { ip, before: bob, after: cob }));
    }

    const cp = tcpOpenPortSet(current);
    const bp = tcpOpenPortSet(base);
    if (cp && bp) {
      const added = [...cp].filter((p) => !bp.has(p)).sort((a, b) => a - b);
      const removed = [...bp].filter((p) => !cp.has(p)).sort((a, b) => a - b);
      if (added.length || removed.length) {
        specs.push(spec("changed_ports", current.id, { ip, added, removed }));
      }
    }
  }

  return specs.length ? db.createAlerts(specs) : [];
}

// Aggregate counts per alert type for the notifier baseline_diff payload.
// Returns {total, counts:{appeared, disappeared, changed_mac, ...}} where
// counts only includes types that fired at least once.
function summarizeAlerts(alerts) {
  const counts = {};
  for (const a of alerts) counts[a.type] = (counts[a.type] || 0) + 1;
  return { total: alerts.length, counts };
}

// v1.13.0 — the notifier tells the two alert families apart: high_latency is
// a statement about the current scan's health, baseline drift is a statement
// about divergence from the declared inventory. Lumping both into one
// "baseline divergence" notification (as v1.12.0 did) mislabels the former
// and makes it impossible to route them to different channels.
// v1.18.0 splits a third family out: sensitive_port is a statement about what
// a device EXPOSES — neither scan health nor baseline drift — and deserves its
// own routing (a telnet box is worth waking someone up for; a slow one isn't).
function partitionAlerts(alerts) {
  const drift = [];
  const latency = [];
  const exposure = [];
  for (const a of alerts || []) {
    if (a.type === "high_latency") latency.push(a);
    else if (a.type === "sensitive_port") exposure.push(a);
    else drift.push(a);
  }
  return { drift, latency, exposure };
}

module.exports = {
  detectAlertsForScan,
  osBucket,
  summarizeAlerts,
  partitionAlerts,
  latencyThresholdMs,
  effectiveLatencyThreshold,
  alertRetentionDays,
  sensitivePorts,
  detectSensitivePortsForHost,
};
