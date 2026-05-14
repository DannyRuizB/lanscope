// v0.10.0 — single source of truth for "run a CIDR sweep against the box's
// own network and persist the result". Owns a global in-process lock so that
// at most one scan runs at a time, regardless of whether it was triggered by
// the manual endpoint, run-now, or a cron tick.
//
// Callers receive { busy } when the lock was held; they decide whether to
// translate that into HTTP 409, a "skipped" schedule row, or just log it.

const db = require("./db");
const { runPingSweep } = require("./scanner");
const { detectAlertsForScan, summarizeAlerts } = require("./alerts");
const notifier = require("./notifier");

let scanInFlight = false;

function isScanInFlight() {
  return scanInFlight;
}

async function executeCidrScan(cidr, { discoveryArgs = [], scheduleId = null } = {}) {
  if (scanInFlight) {
    return { busy: true, scanId: null, scan: null, error: null };
  }
  scanInFlight = true;
  const scanId = db.startScan(cidr, scheduleId);
  try {
    const hosts = await runPingSweep(cidr, { discoveryArgs });
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
    // actually produced alerts.
    if (alerts.length > 0) {
      const baseline = db.getBaselineByCidr(scan.cidr);
      const { total, counts } = summarizeAlerts(alerts);
      notifier
        .dispatch("baseline_diff", {
          scan: {
            id: scan.id,
            cidr: scan.cidr,
            host_count: scan.host_count,
            started_at: scan.started_at,
          },
          baseline: baseline ? { scan_id: baseline.scan_id, set_at: baseline.set_at } : null,
          total,
          counts,
        })
        .catch((e) => console.error(`[runner] dispatch baseline_diff failed: ${e.message}`));
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
