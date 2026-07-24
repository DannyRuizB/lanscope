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

// Unlike the drift detectors below, high latency is a statement about the
// CURRENT scan's health, not about divergence from a declared inventory —
// so it deliberately needs no baseline and fires on any done scan.
function pushLatencySpecs(scan, specs, spec) {
  const threshold = latencyThresholdMs();
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

// Wrap callers in try/catch — a detection failure should never break the
// scan flow. Returns [] when the scan isn't done. The baseline-drift
// detectors additionally need a declared baseline that isn't this very scan
// (self-compare); high_latency runs regardless.
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
function partitionAlerts(alerts) {
  const drift = [];
  const latency = [];
  for (const a of alerts || []) {
    (a.type === "high_latency" ? latency : drift).push(a);
  }
  return { drift, latency };
}

module.exports = {
  detectAlertsForScan,
  osBucket,
  summarizeAlerts,
  partitionAlerts,
  latencyThresholdMs,
};
