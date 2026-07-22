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

test('uptime% counts only the scans that covered the host', () => {
  const C = '10.9.10.0/24';
  // up, down, absent, up → covered = 3 (up/down/up), of which 2 up = 66.7%
  const a = db.startScan(C); db.finishScan(a, [{ ip: '10.9.10.5', status: 'up', latency_ms: 1 }]);
  const b = db.startScan(C); db.finishScan(b, [{ ip: '10.9.10.5', status: 'down' }]);
  const c = db.startScan(C); db.finishScan(c, [{ ip: '10.9.10.6', status: 'up' }]); // 10.5 absent
  const d = db.startScan(C); db.finishScan(d, [{ ip: '10.9.10.5', status: 'up', latency_ms: 2 }]);

  const u = db.getHostHistory(C, '10.9.10.5').uptime;
  assert.equal(u.scans_counted, 3, 'the absent scan is not counted');
  assert.equal(u.scans_up, 2);
  assert.equal(u.pct, 66.7);
});

test('uptime% is null when nothing covered the host (no data, not 0%)', () => {
  const C = '10.9.11.0/24';
  const s = db.startScan(C); db.finishScan(s, [{ ip: '10.9.11.1', status: 'up' }]);
  const u = db.getHostHistory(C, '10.9.11.99').uptime; // never seen
  assert.equal(u.scans_counted, 0);
  assert.equal(u.pct, null);
});

test('historyToCsv keeps a row per scan (gaps included) with a header + BOM', () => {
  const { historyToCsv, historyFilename } = require('../src/export');
  const C = '10.9.12.0/24';
  const a = db.startScan(C); db.finishScan(a, [{ ip: '10.9.12.5', status: 'up', latency_ms: 3 }]);
  const b = db.startScan(C); db.finishScan(b, [{ ip: '10.9.12.6', status: 'up' }]); // 12.5 absent
  const hist = db.getHostHistory(C, '10.9.12.5');
  const csv = historyToCsv(hist);
  assert.ok(csv.startsWith('\uFEFF'), 'UTF-8 BOM for Excel');
  const lines = csv.trim().split('\r\n');
  assert.equal(lines.length, 3, 'header + 2 scans (the absent one kept)');
  assert.match(lines[0], /^\uFEFF?scan_id,started_at,present/);
  assert.ok(lines.some((l) => l.includes(',false,')), 'the absent scan is present=false');
  assert.match(historyFilename(hist, 'csv'), /^lanscope_host-history_10-9-12-5_10-9-12-0-24\.csv$/);
});
