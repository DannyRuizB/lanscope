// v0.10.0 — single source of truth for "run a CIDR sweep against the box's
// own network and persist the result". Owns a global in-process lock so that
// at most one scan runs at a time, regardless of whether it was triggered by
// the manual endpoint, run-now, or a cron tick.
//
// Callers receive { busy } when the lock was held; they decide whether to
// translate that into HTTP 409, a "skipped" schedule row, or just log it.

const db = require("./db");
const { runPingSweep } = require("./scanner");

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
    return { busy: false, scanId, scan: db.getScan(scanId), error: null };
  } catch (e) {
    db.failScan(scanId, e.message);
    return { busy: false, scanId, scan: null, error: e.message };
  } finally {
    scanInFlight = false;
  }
}

module.exports = { executeCidrScan, isScanInFlight };
