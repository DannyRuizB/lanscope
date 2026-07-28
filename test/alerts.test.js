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
const {
  detectAlertsForScan,
  detectSensitivePortsForHost,
  latencyThresholdMs,
  partitionAlerts,
  sensitivePorts,
} = require('../src/alerts');

// Each test gets its own CIDR so scans/baselines never bleed across tests.
let n = 0;
let CIDR;
beforeEach(() => {
  n += 1;
  CIDR = `10.50.${n}.0/24`;
  delete process.env.LATENCY_ALERT_MS;
  delete process.env.SENSITIVE_PORTS;
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
  const empty = { drift: [], latency: [], exposure: [] };
  assert.deepEqual(partitionAlerts([]), empty);
  assert.deepEqual(partitionAlerts(null), empty);
  assert.deepEqual(partitionAlerts(undefined), empty);
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

// --- getDigest (v1.15.0) ----------------------------------------------------

test('getDigest rolls up scans, new alerts and pending backlog by CIDR', () => {
  const other = `10.90.${n}.0/24`;
  const a = doneScan([{ ip: `10.50.${n}.1`, status: 'up' }]);
  doneScan([{ ip: `10.50.${n}.1`, status: 'up' }]); // second scan, same CIDR
  const c = db.startScan(other); db.finishScan(c, [{ ip: `10.90.${n}.1`, status: 'up' }]);
  db.createAlerts([
    { scan_id: a, host_id: null, cidr: CIDR, type: 'appeared', payload: {} },
    { scan_id: a, host_id: null, cidr: CIDR, type: 'appeared', payload: {} },
    { scan_id: a, host_id: null, cidr: CIDR, type: 'changed_ports', payload: {} },
  ]);
  const d = db.getDigest(0);
  const mine = d.cidrs.find((x) => x.cidr === CIDR);
  assert.equal(mine.scans, 2);
  assert.equal(mine.alerts_new.appeared, 2);
  assert.equal(mine.alerts_new.changed_ports, 1);
  assert.equal(mine.alerts_new_total, 3);
  assert.equal(mine.alerts_pending, 3); // all unacked
  const theirs = d.cidrs.find((x) => x.cidr === other);
  assert.equal(theirs.scans, 1);
  assert.equal(theirs.alerts_new_total, 0);
});

test('getDigest excludes CIDRs with no activity in the window', () => {
  // A scan far in the past: with a recent `since`, its CIDR must not appear.
  const old = db.startScan(`10.91.${n}.0/24`);
  db.finishScan(old, [{ ip: `10.91.${n}.1`, status: 'up' }]);
  const future = Date.now() + 3600 * 1000;
  const d = db.getDigest(future);
  assert.equal(d.cidrs.length, 0);
  assert.equal(d.totals.scans, 0);
});

// --- sensitive_port (v1.18.0) ----------------------------------------------

// Ports live in their own table, saved per host after the scan finishes —
// mirror what the runner does: finish the scan, then attach ports by host id.
function doneScanWithPorts(hosts) {
  const id = doneScan(hosts.map(({ ports, ...h }) => h)); // eslint-disable-line no-unused-vars
  const saved = db.getScan(id).hosts;
  hosts.forEach((h, i) => {
    if (h.ports) db.saveHostPorts(saved[i].id, h.ports, []);
  });
  return id;
}

test('sensitivePorts: unset/blank/garbage means OFF; a valid list parses sorted and deduped', () => {
  for (const bad of [undefined, '', '   ', 'abc', 'zero,none', '0', '-5', '70000']) {
    if (bad === undefined) delete process.env.SENSITIVE_PORTS;
    else process.env.SENSITIVE_PORTS = bad;
    assert.equal(sensitivePorts(), null, `expected OFF for ${JSON.stringify(bad)}`);
  }
  process.env.SENSITIVE_PORTS = '3389, 23,445 ,23';
  assert.deepEqual(sensitivePorts(), [23, 445, 3389]);
  // A partly-bad list keeps the usable entries rather than failing shut.
  process.env.SENSITIVE_PORTS = '23,nope,99999,445';
  assert.deepEqual(sensitivePorts(), [23, 445]);
  delete process.env.SENSITIVE_PORTS;
});

test('with the watchlist unset, no sensitive_port alerts fire (the default)', () => {
  const id = doneScanWithPorts([
    { ip: `10.50.${n}.1`, status: 'up', ports: [{ port: 23, protocol: 'tcp', state: 'open', service: 'telnet' }] },
  ]);
  assert.equal(detectAlertsForScan(id).filter((a) => a.type === 'sensitive_port').length, 0);
});

test('one alert per host listing every watched port open on it', () => {
  process.env.SENSITIVE_PORTS = '23,445,3389';
  const id = doneScanWithPorts([
    {
      ip: `10.50.${n}.1`,
      status: 'up',
      hostname: 'legacy.lan',
      ports: [
        { port: 23, protocol: 'tcp', state: 'open', service: 'telnet' },
        { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
        { port: 80, protocol: 'tcp', state: 'open', service: 'http' }, // not watched
      ],
    },
  ]);
  const hits = detectAlertsForScan(id).filter((a) => a.type === 'sensitive_port');
  assert.equal(hits.length, 1, 'one alert per host, not per port');
  assert.equal(hits[0].payload.ip, `10.50.${n}.1`);
  assert.equal(hits[0].payload.hostname, 'legacy.lan');
  assert.deepEqual(hits[0].payload.ports.map((p) => p.port), [23, 445]);
  assert.deepEqual(hits[0].payload.watchlist, [23, 445, 3389]);
  delete process.env.SENSITIVE_PORTS;
});

test('closed/filtered watched ports, unscanned hosts and down hosts stay quiet', () => {
  process.env.SENSITIVE_PORTS = '23,3389';
  const id = doneScanWithPorts([
    { ip: `10.50.${n}.1`, status: 'up', ports: [{ port: 23, protocol: 'tcp', state: 'closed', service: 'telnet' }] },
    { ip: `10.50.${n}.2`, status: 'up', ports: [{ port: 3389, protocol: 'tcp', state: 'filtered' }] },
    { ip: `10.50.${n}.3`, status: 'up' }, // never port-scanned: says nothing
    { ip: `10.50.${n}.4`, status: 'down', ports: [{ port: 23, protocol: 'tcp', state: 'open' }] },
  ]);
  assert.equal(detectAlertsForScan(id).filter((a) => a.type === 'sensitive_port').length, 0);
  delete process.env.SENSITIVE_PORTS;
});

// The LIVE hook — what the portscan endpoint calls the moment ports land.
// The scan-level tests above can't exercise the dedupe guard: they judge a
// scan exactly once, while a host can be port-scanned again and again.
test('live hook: fires once ports land, dedupes while pending, re-fires after an ack', () => {
  process.env.SENSITIVE_PORTS = '23';
  const id = doneScan([{ ip: `10.50.${n}.1`, status: 'up', hostname: 'legacy.lan' }]);
  const host = db.getScan(id).hosts[0];
  // Before any port scan the host says nothing about its ports.
  assert.equal(detectSensitivePortsForHost(host.id).length, 0);
  db.saveHostPorts(host.id, [{ port: 23, protocol: 'tcp', state: 'open', service: 'telnet' }], []);
  const first = detectSensitivePortsForHost(host.id);
  assert.equal(first.length, 1);
  assert.equal(first[0].type, 'sensitive_port');
  assert.deepEqual(first[0].payload.ports.map((p) => p.port), [23]);
  // A re-scan while the finding is untriaged must not pile up duplicates…
  assert.equal(detectSensitivePortsForHost(host.id).length, 0);
  // …but an acknowledged one does not block fresh news.
  db.ackAlert(first[0].id);
  assert.equal(detectSensitivePortsForHost(host.id).length, 1);
  delete process.env.SENSITIVE_PORTS;
});

test('live hook stays quiet: watchlist off, host down, or nothing watched open', () => {
  const id = doneScan([
    { ip: `10.50.${n}.1`, status: 'up' },
    { ip: `10.50.${n}.2`, status: 'down' },
  ]);
  const [up, down] = db.getScan(id).hosts;
  db.saveHostPorts(up.id, [{ port: 23, protocol: 'tcp', state: 'open', service: 'telnet' }], []);
  db.saveHostPorts(down.id, [{ port: 23, protocol: 'tcp', state: 'open', service: 'telnet' }], []);
  assert.equal(detectSensitivePortsForHost(up.id).length, 0, 'no watchlist set');
  process.env.SENSITIVE_PORTS = '23';
  assert.equal(detectSensitivePortsForHost(down.id).length, 0, 'down host');
  process.env.SENSITIVE_PORTS = '3389';
  assert.equal(detectSensitivePortsForHost(up.id).length, 0, 'open port not on the watchlist');
  delete process.env.SENSITIVE_PORTS;
});

test('sensitive_port needs no baseline (like high_latency) and partitions into its own family', () => {
  process.env.SENSITIVE_PORTS = '23';
  const id = doneScanWithPorts([
    { ip: `10.50.${n}.1`, status: 'up', ports: [{ port: 23, protocol: 'tcp', state: 'open', service: 'telnet' }] },
  ]);
  // No baseline declared for this CIDR at all, and it still fires.
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.filter((a) => a.type === 'sensitive_port').length, 1);
  const { drift, latency, exposure } = partitionAlerts(alerts);
  assert.equal(exposure.length, 1);
  assert.equal(latency.length, 0);
  assert.equal(drift.length, 0, 'exposure findings must not be reported as baseline drift');
  delete process.env.SENSITIVE_PORTS;
});
