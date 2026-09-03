// v0.10.0 — single source of truth for "run a CIDR sweep against the box's
// own network and persist the result". Owns a global in-process lock so that
// at most one scan runs at a time, regardless of whether it was triggered by
// the manual endpoint, run-now, or a cron tick.
//
// Callers receive { busy } when the lock was held; they decide whether to
// translate that into HTTP 409, a "skipped" schedule row, or just log it.

const db = require("./db");
const { runPingSweep } = require("./scanner");
const { detectAlertsForScan, summarizeAlerts, partitionAlerts } = require("./alerts");
const notifier = require("./notifier");

let scanInFlight = false;

function isScanInFlight() {
  return scanInFlight;
}

async function executeCidrScan(cidr, { discoveryArgs = [], excludeArgs = [], rateArgs = [], scheduleId = null } = {}) {
  if (scanInFlight) {
    return { busy: true, scanId: null, scan: null, error: null };
  }
  scanInFlight = true;
  const scanId = db.startScan(cidr, scheduleId);
  try {
    const hosts = await runPingSweep(cidr, { discoveryArgs, excludeArgs, rateArgs });
    db.finishScan(scanId, hosts);
    let alerts = [];
    try {
      alerts = detectAlertsForScan(scanId);
    } catch (e) {
      console.error("[alerts] detect failed for scan", scanId, e);
    }
    const scan = db.getScan(scanId);
    // v0.13.0 — fire baseline_diff once with aggregated counts. Fire-and-forget
    // so a slow webhook never blocks the scan response. Only when the diff
    // actually produced alerts. Since v1.13.0 high_latency alerts get their
    // own event below instead of riding in the divergence digest — they carry
    // no baseline claim, and splitting them lets a channel subscribe to one
    // without the other. The third family (sensitive_port, v1.18.0) is never
    // dispatched from here: a sweep records no ports, so a live scan cannot
    // produce exposure alerts — the portscan endpoint owns that dispatch.
    const { drift, latency } = partitionAlerts(alerts);
    const scanCtx = {
      id: scan.id,
      cidr: scan.cidr,
      host_count: scan.host_count,
      started_at: scan.started_at,
    };
    if (drift.length > 0) {
      const baseline = db.getBaselineByCidr(scan.cidr);
      const { total, counts } = summarizeAlerts(drift);
      notifier
        .dispatch("baseline_diff", {
          scan: scanCtx,
          baseline: baseline ? { scan_id: baseline.scan_id, set_at: baseline.set_at } : null,
          total,
          counts,
        })
        .catch((e) => console.error(`[runner] dispatch baseline_diff failed: ${e.message}`));
    }
    if (latency.length > 0) {
      // Worst offenders first; cap the list so a /16 with a bad uplink doesn't
      // turn the notification into a phone book (total still says how many).
      const slow = latency
        .map((a) => a.payload || {})
        .sort((x, y) => (y.latency_ms ?? 0) - (x.latency_ms ?? 0));
      notifier
        .dispatch("high_latency", {
          scan: scanCtx,
          total: latency.length,
          threshold_ms: slow[0]?.threshold_ms ?? null,
          slow_hosts: slow.slice(0, 5).map((p) => ({
            ip: p.ip ?? null,
            hostname: p.hostname ?? null,
            latency_ms: p.latency_ms ?? null,
          })),
        })
        .catch((e) => console.error(`[runner] dispatch high_latency failed: ${e.message}`));
    }
    return { busy: false, scanId, scan, alerts, error: null };
  } catch (e) {
    db.failScan(scanId, e.message);
    return { busy: false, scanId, scan: null, alerts: [], error: e.message };
  } finally {
    scanInFlight = false;
  }
}

module.exports = { executeCidrScan, isScanInFlight };
