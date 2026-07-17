'use strict';

// getHostHistory needs a real SQLite — point DB_PATH at a throwaway file
// BEFORE requiring db (the module opens the database at import time; the
// test runner gives each test file its own process, so this can't leak).
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

const CIDR = '10.9.9.0/24';

test('getHostHistory tells presence, latency and port counts apart', () => {
  const s1 = db.startScan(CIDR);
  db.finishScan(s1, [
    { ip: '10.9.9.5', status: 'up', latency_ms: 1.5 },
    { ip: '10.9.9.9', status: 'up', latency_ms: 40 },
  ]);
  const s2 = db.startScan(CIDR);
  db.finishScan(s2, [{ ip: '10.9.9.5', status: 'up', latency_ms: 2.5 }]);
  const host2 = db.getScan(s2).hosts.find((h) => h.ip === '10.9.9.5');
  db.saveHostPorts(host2.id, [
    { port: 22, state: 'open' },
    { port: 80, state: 'closed' },
  ], []);

  const hist = db.getHostHistory(CIDR, '10.9.9.5');
  assert.equal(hist.cidr, CIDR);
  assert.equal(hist.points.length, 2);
  // Two scans can share a Date.now() millisecond — pick by scan id, then
  // check the series is chronological rather than assuming positions.
  const p1 = hist.points.find((p) => p.scan_id === s1);
  const p2 = hist.points.find((p) => p.scan_id === s2);
  assert.ok(hist.points[0].started_at <= hist.points[1].started_at, 'chronological');
  assert.equal(p1.present, true);
  assert.equal(p1.latency_ms, 1.5);
  // Scan 1 never port-scanned the host: "not scanned" is null, not zero.
  assert.equal(p1.tcp_open_ports, null);
  // Scan 2 did: only OPEN ports count (80 is closed).
  assert.equal(p2.tcp_open_ports, 1);
  assert.equal(p2.latency_ms, 2.5);

  // A host that vanished keeps its slot in the series, flagged absent.
  const gone = db.getHostHistory(CIDR, '10.9.9.9');
  assert.equal(gone.points.length, 2);
  assert.equal(gone.points.find((p) => p.scan_id === s1).present, true);
  const after = gone.points.find((p) => p.scan_id === s2);
  assert.equal(after.present, false);
  assert.equal(after.latency_ms, null);
  assert.equal(after.tcp_open_ports, null);

  // Unknown network → empty series, not an error.
  assert.equal(db.getHostHistory('172.31.0.0/24', '172.31.0.1').points.length, 0);
});
