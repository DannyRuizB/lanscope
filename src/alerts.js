// v0.13.0 — detector of baseline-divergence alerts.
//
// Called after every successful CIDR sweep. Compares the freshly stored scan
// against the declared inventory_baselines row for the same CIDR (if any) and
// writes one alert row per detected change.
//
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

// Inspect a completed scan and emit alerts vs the CIDR's declared baseline.
// Returns the array of alerts created (already persisted). Returns [] when:
//   - the scan doesn't exist or isn't 'done'
//   - the CIDR has no declared baseline
//   - the scan IS the baseline (self-compare would emit zero anyway, but skip
//     the work)
// Wrap callers in try/catch — a detection failure should never break the scan
// flow.
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

  const created = [];

  for (const [ip, h] of currentByIp) {
    if (baselineByIp.has(ip)) continue;
    created.push(
      db.createAlert({
        scan_id: scanId,
        host_id: h.id,
        cidr: scan.cidr,
        type: "appeared",
        payload: {
          ip,
          mac: h.mac || null,
          hostname: h.hostname || null,
          vendor: h.vendor || null,
        },
      }),
    );
  }

  for (const [ip, b] of baselineByIp) {
    if (currentByIp.has(ip)) continue;
    created.push(
      db.createAlert({
        scan_id: scanId,
        host_id: null,
        cidr: scan.cidr,
        type: "disappeared",
        payload: {
          ip,
          last_seen_mac: b.mac || null,
          last_seen_hostname: b.hostname || null,
          last_seen_vendor: b.vendor || null,
        },
      }),
    );
  }

  for (const [ip, current] of currentByIp) {
    const base = baselineByIp.get(ip);
    if (!base) continue;

    const cm = normMac(current.mac);
    const bm = normMac(base.mac);
    if (cm && bm && cm !== bm) {
      created.push(
        db.createAlert({
          scan_id: scanId,
          host_id: current.id,
          cidr: scan.cidr,
          type: "changed_mac",
          payload: { ip, before: base.mac, after: current.mac },
        }),
      );
    }

    const ch = normName(current.hostname);
    const bh = normName(base.hostname);
    if (ch && bh && ch !== bh) {
      created.push(
        db.createAlert({
          scan_id: scanId,
          host_id: current.id,
          cidr: scan.cidr,
          type: "changed_hostname",
          payload: { ip, before: base.hostname, after: current.hostname },
        }),
      );
    }

    const cob = osBucket(current);
    const bob = osBucket(base);
    if (cob && bob && cob !== bob) {
      created.push(
        db.createAlert({
          scan_id: scanId,
          host_id: current.id,
          cidr: scan.cidr,
          type: "changed_os",
          payload: { ip, before: bob, after: cob },
        }),
      );
    }

    const cp = tcpOpenPortSet(current);
    const bp = tcpOpenPortSet(base);
    if (cp && bp) {
      const added = [...cp].filter((p) => !bp.has(p)).sort((a, b) => a - b);
      const removed = [...bp].filter((p) => !cp.has(p)).sort((a, b) => a - b);
      if (added.length || removed.length) {
        created.push(
          db.createAlert({
            scan_id: scanId,
            host_id: current.id,
            cidr: scan.cidr,
            type: "changed_ports",
            payload: { ip, added, removed },
          }),
        );
      }
    }
  }

  return created;
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
