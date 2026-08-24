'use strict';

// getMetricsSnapshot needs a real SQLite — point DB_PATH at a throwaway
// file BEFORE requiring db (the module opens the database at import time;
// the test runner gives each test file its own process, so this can't
// leak). The buildMetrics half is pure and needs none of that.
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
process.env.DB_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-test-')),
  'test.db',
);

const { test } = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const { buildMetrics, escapeLabelValue } = require('../src/metrics');

// --- buildMetrics (pure) ---------------------------------------------------

const EMPTY_SNAPSHOT = {
  scansStored: 0,
  scansRunning: 0,
  networks: [],
  alertsPending: {},
  schedulesEnabled: 0,
  schedulesTotal: 0,
};

test('every family gets HELP + TYPE exactly once, even with zero series', () => {
  const text = buildMetrics(EMPTY_SNAPSHOT, {
    version: '9.9.9',
    alertTypes: db.ALERT_TYPES,
  });
  for (const name of [
    'lanscope_info',
    'lanscope_scans_stored',
    'lanscope_scans_running',
    'lanscope_hosts_up',
    'lanscope_hosts_total',
    'lanscope_last_scan_timestamp_seconds',
    'lanscope_last_scan_duration_seconds',
    'lanscope_alerts_pending',
    'lanscope_schedules_enabled',
    'lanscope_schedules_total',
  ]) {
    assert.equal(
      text.split('\n').filter((l) => l.startsWith(`# HELP ${name} `)).length,
      1,
      `one HELP for ${name}`,
    );
    assert.equal(
      text.split('\n').filter((l) => l === `# TYPE ${name} gauge`).length,
      1,
      `one gauge TYPE for ${name}`,
    );
  }
  assert.ok(text.endsWith('\n'), 'exposition ends with a newline');
  assert.ok(text.includes('lanscope_info{version="9.9.9"} 1'));
});

test('pending alerts are zero-filled over every known type', () => {
  const text = buildMetrics(
    { ...EMPTY_SNAPSHOT, alertsPending: { appeared: 3 } },
    { version: '1.0.0', alertTypes: db.ALERT_TYPES },
  );
  assert.ok(text.includes('lanscope_alerts_pending{type="appeared"} 3'));
  for (const t of db.ALERT_TYPES.filter((t) => t !== 'appeared')) {
    assert.ok(
      text.includes(`lanscope_alerts_pending{type="${t}"} 0`),
      `type ${t} present as 0`,
    );
  }
});

test('per-network series carry the cidr label; ms convert to seconds', () => {
  const text = buildMetrics(
    {
      ...EMPTY_SNAPSHOT,
      networks: [
        {
          cidr: '192.168.1.0/24',
          hostsUp: 11,
          hostsTotal: 13,
          lastScanFinishedAt: 1700000000500,
          lastScanDurationMs: 4250,
        },
        // A scan that never finished contributes counts but no clocks.
        {
          cidr: '10.0.0.0/24',
          hostsUp: 0,
          hostsTotal: 0,
          lastScanFinishedAt: null,
          lastScanDurationMs: null,
        },
      ],
    },
    { version: '1.0.0', alertTypes: db.ALERT_TYPES },
  );
  assert.ok(text.includes('lanscope_hosts_up{cidr="192.168.1.0/24"} 11'));
  assert.ok(text.includes('lanscope_hosts_total{cidr="192.168.1.0/24"} 13'));
  assert.ok(
    text.includes(
      'lanscope_last_scan_timestamp_seconds{cidr="192.168.1.0/24"} 1700000000.5',
    ),
  );
  assert.ok(
    text.includes(
      'lanscope_last_scan_duration_seconds{cidr="192.168.1.0/24"} 4.25',
    ),
  );
  assert.ok(text.includes('lanscope_hosts_up{cidr="10.0.0.0/24"} 0'));
  assert.ok(
    !text.includes('lanscope_last_scan_timestamp_seconds{cidr="10.0.0.0/24"}'),
    'no timestamp series for a network without a finished clock',
  );
});

test('label values escape backslash, quote and newline', () => {
  assert.equal(escapeLabelValue('a\\b'), 'a\\\\b');
  assert.equal(escapeLabelValue('a"b'), 'a\\"b');
  assert.equal(escapeLabelValue('a\nb'), 'a\\nb');
});

// --- getMetricsSnapshot (real SQLite) ---------------------------------------

test('snapshot reports the LATEST finished scan per network, running scans aside', () => {
  const cidr = '10.90.1.0/24';
  const first = db.startScan(cidr, null);
  db.finishScan(first, [
    { ip: '10.90.1.1', status: 'up' },
    { ip: '10.90.1.2', status: 'up' },
    { ip: '10.90.1.3', status: 'down' },
  ]);
  const second = db.startScan(cidr, null);
  db.finishScan(second, [
    { ip: '10.90.1.1', status: 'up' },
    { ip: '10.90.1.3', status: 'down' },
  ]);
  db.startScan(cidr, null); // still running — must not represent the network

  const snap = db.getMetricsSnapshot();
  assert.equal(snap.scansStored, 3);
  assert.equal(snap.scansRunning, 1);
  const net = snap.networks.find((n) => n.cidr === cidr);
  assert.ok(net, 'network present');
  assert.equal(net.hostsUp, 1, 'counts come from the SECOND scan');
  assert.equal(net.hostsTotal, 2);
  assert.ok(net.lastScanFinishedAt != null);
  assert.ok(net.lastScanDurationMs >= 0);
});

test('snapshot groups pending alerts by type and skips acked ones', () => {
  const cidr = '10.90.2.0/24';
  const scanId = db.startScan(cidr, null);
  db.finishScan(scanId, [{ ip: '10.90.2.7', status: 'up' }]);
  db.createAlert({ scan_id: scanId, cidr, type: 'appeared', payload: { ip: '10.90.2.7' } });
  db.createAlert({ scan_id: scanId, cidr, type: 'appeared', payload: { ip: '10.90.2.8' } });
  const acked = db.createAlert({
    scan_id: scanId, cidr, type: 'high_latency', payload: { ip: '10.90.2.7' },
  });
  db.ackAlert(acked.id);

  const snap = db.getMetricsSnapshot();
  assert.equal(snap.alertsPending.appeared, 2);
  assert.equal(snap.alertsPending.high_latency, undefined, 'acked rows never count');
});

test('snapshot counts schedules and how many are enabled', () => {
  db.createSchedule({
    name: 'metrics fixture on',
    cidr: '10.90.3.0/24',
    cron_expr: '0 * * * *',
    enabled: true,
    scan_options: null,
  });
  db.createSchedule({
    name: 'metrics fixture off',
    cidr: '10.90.3.0/24',
    cron_expr: '0 * * * *',
    enabled: false,
    scan_options: null,
  });
  const snap = db.getMetricsSnapshot();
  assert.equal(snap.schedulesTotal, 2);
  assert.equal(snap.schedulesEnabled, 1);
});
