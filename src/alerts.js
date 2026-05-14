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

// Wrap callers in try/catch — a detection failure should never break the
// scan flow. Returns [] when the scan isn't done, the CIDR has no declared
// baseline, or the scan IS the baseline (self-compare).
function detectAlertsForScan(scanId) {
  const scan = db.getScan(scanId);
  if (!scan || scan.status !== "done") return [];

  const baseline = db.getBaselineByCidr(scan.cidr);
  if (!baseline) return [];
  if (baseline.scan_id === scanId) return [];

  const baselineScan = db.getScan(baseline.scan_id);
  if (!baselineScan) return [];

  const currentByIp = new Map();
  for (const h of scan.hosts || []) {
    if (h.status === "up") currentByIp.set(h.ip, h);
  }
  const baselineByIp = new Map();
  for (const h of baselineScan.hosts || []) {
    if (h.status === "up") baselineByIp.set(h.ip, h);
  }

  const specs = [];
  const spec = (type, host_id, payload) => ({
    scan_id: scanId,
    host_id,
    cidr: scan.cidr,
    type,
    payload,
  });

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

module.exports = { detectAlertsForScan, osBucket, summarizeAlerts };
