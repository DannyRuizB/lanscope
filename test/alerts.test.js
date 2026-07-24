'use strict';

// detectAlertsForScan needs a real SQLite — point DB_PATH at a throwaway
// file BEFORE requiring db (the module opens the database at import time;
// the test runner gives each test file its own process, so this can't leak).
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
process.env.DB_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-test-')),
  'test.db',
);

const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const { detectAlertsForScan, latencyThresholdMs, partitionAlerts } = require('../src/alerts');

// Each test gets its own CIDR so scans/baselines never bleed across tests.
let n = 0;
let CIDR;
beforeEach(() => {
  n += 1;
  CIDR = `10.50.${n}.0/24`;
  delete process.env.LATENCY_ALERT_MS;
});

function doneScan(hosts) {
  const id = db.startScan(CIDR);
  db.finishScan(id, hosts);
  return id;
}

test('latencyThresholdMs: unset/blank/garbage/zero/negative all mean OFF', () => {
  for (const bad of [undefined, '', '   ', 'abc', '0', '-5', 'NaN']) {
    if (bad === undefined) delete process.env.LATENCY_ALERT_MS;
    else process.env.LATENCY_ALERT_MS = bad;
    assert.equal(latencyThresholdMs(), null, `expected OFF for ${JSON.stringify(bad)}`);
  }
  process.env.LATENCY_ALERT_MS = '50';
  assert.equal(latencyThresholdMs(), 50);
  process.env.LATENCY_ALERT_MS = '12.5';
  assert.equal(latencyThresholdMs(), 12.5);
});

test('with the threshold unset, no high_latency alerts fire (the default)', () => {
  const id = doneScan([{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 900 }]);
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.filter((a) => a.type === 'high_latency').length, 0);
});

test('hosts at or over the threshold alert; under, untimed and down ones do not', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const id = doneScan([
    { ip: `10.50.${n}.1`, status: 'up', latency_ms: 85, hostname: 'repeater.lan' },
    { ip: `10.50.${n}.2`, status: 'up', latency_ms: 50 }, // exactly at → fires
    { ip: `10.50.${n}.3`, status: 'up', latency_ms: 49.9 },
    { ip: `10.50.${n}.4`, status: 'up', latency_ms: null }, // not timed ≠ slow
    { ip: `10.50.${n}.5`, status: 'down', latency_ms: 200 },
  ]);
  const alerts = detectAlertsForScan(id).filter((a) => a.type === 'high_latency');
  assert.equal(alerts.length, 2);
  const byIp = Object.fromEntries(alerts.map((a) => [a.payload.ip, a]));
  assert.equal(byIp[`10.50.${n}.1`].payload.latency_ms, 85);
  assert.equal(byIp[`10.50.${n}.1`].payload.threshold_ms, 50);
  assert.equal(byIp[`10.50.${n}.1`].payload.hostname, 'repeater.lan');
  assert.ok(byIp[`10.50.${n}.2`], 'a host exactly at the threshold fires');
});

test('high_latency needs no baseline — health, not drift', () => {
  process.env.LATENCY_ALERT_MS = '10';
  assert.equal(db.getBaselineByCidr(CIDR), null, 'precondition: no baseline');
  const id = doneScan([{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 30 }]);
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].type, 'high_latency');
  // Persisted, not just returned: the alerts API sees it.
  const stored = db.listAlerts({ cidr: CIDR });
  assert.equal(stored.length, 1);
  assert.equal(stored[0].type, 'high_latency');
});

test('latency alerts also fire on the baseline scan itself (no self-compare rule)', () => {
  process.env.LATENCY_ALERT_MS = '10';
  const id = doneScan([{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 30 }]);
  db.setBaseline(id);
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.filter((a) => a.type === 'high_latency').length, 1);
  assert.equal(alerts.filter((a) => a.type !== 'high_latency').length, 0,
    'drift detectors still skip the self-compare');
});

test('drift alerts and latency alerts fire together against a baseline', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const base = doneScan([{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 5 }]);
  db.setBaseline(base);
  const id = doneScan([
    { ip: `10.50.${n}.1`, status: 'up', latency_ms: 90 }, // slow now
    { ip: `10.50.${n}.2`, status: 'up', latency_ms: 1 }, // new host
  ]);
  const types = detectAlertsForScan(id).map((a) => a.type).sort();
  assert.equal(JSON.stringify(types), JSON.stringify(['appeared', 'high_latency']));
});

// --- partitionAlerts (v1.13.0) --------------------------------------------

test('partitionAlerts splits high_latency from drift preserving order', () => {
  const a = { type: 'appeared' };
  const b = { type: 'high_latency' };
  const c = { type: 'changed_ports' };
  const d = { type: 'high_latency' };
  const { drift, latency } = partitionAlerts([a, b, c, d]);
  assert.deepEqual(drift, [a, c]);
  assert.deepEqual(latency, [b, d]);
});

test('partitionAlerts tolerates empty and missing input', () => {
  assert.deepEqual(partitionAlerts([]), { drift: [], latency: [] });
  assert.deepEqual(partitionAlerts(null), { drift: [], latency: [] });
  assert.deepEqual(partitionAlerts(undefined), { drift: [], latency: [] });
});

// --- per-schedule latency threshold (v1.14.0) -------------------------------

function doneScheduledScan(scheduleId, hosts) {
  const id = db.startScan(CIDR, scheduleId);
  db.finishScan(id, hosts);
  return id;
}

test('a schedule with its own latency_alert_ms fires without the global env', () => {
  const sched = db.createSchedule({
    name: `own-threshold-${n}`, cidr: CIDR, cron_expr: '0 3 * * *',
    enabled: false, latency_alert_ms: 100,
  });
  const id = doneScheduledScan(sched.id, [
    { ip: `10.50.${n}.1`, status: 'up', latency_ms: 150 },
    { ip: `10.50.${n}.2`, status: 'up', latency_ms: 50 },
  ]);
  const alerts = detectAlertsForScan(id).filter((a) => a.type === 'high_latency');
  assert.equal(alerts.length, 1, 'only the 150ms host crosses the schedule bar');
  assert.equal(alerts[0].payload.threshold_ms, 100);
});

test('latency_alert_ms: 0 turns alerts OFF for that schedule even with the env set', () => {
  process.env.LATENCY_ALERT_MS = '10';
  const sched = db.createSchedule({
    name: `muted-${n}`, cidr: CIDR, cron_expr: '0 3 * * *',
    enabled: false, latency_alert_ms: 0,
  });
  const id = doneScheduledScan(sched.id, [{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 500 }]);
  assert.equal(detectAlertsForScan(id).filter((a) => a.type === 'high_latency').length, 0);
});

test('latency_alert_ms: null inherits the global env; manual scans always use it', () => {
  process.env.LATENCY_ALERT_MS = '100';
  const sched = db.createSchedule({
    name: `inherit-${n}`, cidr: CIDR, cron_expr: '0 3 * * *',
    enabled: false, latency_alert_ms: null,
  });
  const scheduled = doneScheduledScan(sched.id, [{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 150 }]);
  assert.equal(detectAlertsForScan(scheduled).filter((a) => a.type === 'high_latency').length, 1);
  // Manual scan (no schedule) on the same CIDR: env applies too.
  const manual = doneScan([{ ip: `10.50.${n}.2`, status: 'up', latency_ms: 150 }]);
  assert.equal(detectAlertsForScan(manual).filter((a) => a.type === 'high_latency').length, 1);
});

test('a stricter schedule bar fires where the laxer global would not', () => {
  process.env.LATENCY_ALERT_MS = '1000';
  const sched = db.createSchedule({
    name: `strict-${n}`, cidr: CIDR, cron_expr: '0 3 * * *',
    enabled: false, latency_alert_ms: 50,
  });
  const id = doneScheduledScan(sched.id, [{ ip: `10.50.${n}.1`, status: 'up', latency_ms: 80 }]);
  const alerts = detectAlertsForScan(id).filter((a) => a.type === 'high_latency');
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].payload.threshold_ms, 50);
});
