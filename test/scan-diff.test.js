'use strict';

// The diff export needs a real SQLite for its round-trip half — point
// DB_PATH at a throwaway file BEFORE requiring db (the module opens the
// database at import time; node --test isolates each file in its own
// process, so this can't leak).
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
process.env.DB_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-test-')),
  'test.db',
);

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { diffScans, hostChangeReasons, osBucketKey } = require('../src/public/scan-diff');
const { diffToCsv, diffFilename } = require('../src/export');
const db = require('../src/db');

function up(ip, extra = {}) {
  return { ip, status: 'up', mac: null, hostname: null, ...extra };
}

test('diffScans classifies appeared, disappeared, changed and unchanged', () => {
  const base = { hosts: [
    up('10.0.0.1'),
    up('10.0.0.2', { hostname: 'nas' }),
    up('10.0.0.3', { mac: 'AA:BB:CC:DD:EE:01' }),
    { ip: '10.0.0.9', status: 'down' },
  ] };
  const next = { hosts: [
    up('10.0.0.2', { hostname: 'nas-new' }),
    up('10.0.0.3', { mac: 'AA:BB:CC:DD:EE:02' }),
    up('10.0.0.4'),
    { ip: '10.0.0.9', status: 'down' },
  ] };
  const d = diffScans(base, next);
  assert.deepEqual(d.appeared.map((h) => h.ip), ['10.0.0.4']);
  assert.deepEqual(d.disappeared.map((h) => h.ip), ['10.0.0.1']);
  assert.deepEqual(d.changed.map((c) => [c.host.ip, c.reasons.join('+')]).sort(),
    [['10.0.0.2', 'hostname'], ['10.0.0.3', 'mac']]);
  assert.equal(d.unchanged.length, 0);
  // Down rows are absence, not presence: 10.0.0.9 is in neither side.
  assert.equal(d.byIp.has('10.0.0.9'), false);
  assert.equal(d.byIp.get('10.0.0.4').state, 'appeared');
});

test('an OS change only counts when BOTH sides were scanned and neither is unknown', () => {
  const winHost = { osscanned_at: 1, os_matches: [{ family: 'Windows' }] };
  const linHost = { osscanned_at: 1, os_matches: [{ family: 'Linux' }] };
  const notScanned = { osscanned_at: null, os_matches: [] };
  const noMatch = { osscanned_at: 1, os_matches: [] };
  assert.equal(osBucketKey(winHost), 'windows');
  assert.equal(osBucketKey(notScanned), 'unknown');
  assert.equal(osBucketKey(noMatch), 'unknown');
  assert.deepEqual(hostChangeReasons({ ...winHost }, { ...linHost }), ['os']);
  assert.deepEqual(hostChangeReasons({ ...notScanned }, { ...linHost }), []);
  assert.deepEqual(hostChangeReasons({ ...noMatch }, { ...linHost }), []);
});

test('diffToCsv: state first, one row per classified host, base values on changed rows', () => {
  const diff = diffScans(
    { hosts: [up('10.0.0.2', { hostname: 'nas', mac: 'AA:01' }), up('10.0.0.1')] },
    { hosts: [up('10.0.0.2', { hostname: 'nas, prod', mac: 'AA:01' }), up('10.0.0.4')] },
  );
  const csv = diffToCsv(diff, { '10.0.0.4': 'new printer' });
  assert.ok(csv.startsWith('\uFEFF'), 'BOM for Excel');
  const lines = csv.slice(1).trimEnd().split('\r\n');
  assert.equal(lines[0], 'state,ip,label,mac,vendor,hostname,reasons,base_mac,base_hostname');
  assert.equal(lines.length, 4); // header + appeared + disappeared + changed
  const appeared = lines.find((l) => l.startsWith('appeared'));
  assert.match(appeared, /^appeared,10\.0\.0\.4,new printer,/);
  const gone = lines.find((l) => l.startsWith('disappeared'));
  assert.match(gone, /^disappeared,10\.0\.0\.1,/);
  const changed = lines.find((l) => l.startsWith('changed'));
  // The new hostname carries a comma — RFC 4180 quoting — and the base
  // hostname rides along so the file shows WHAT changed.
  assert.match(changed, /"nas, prod"/);
  assert.match(changed, /hostname/);
  assert.match(changed, /nas$/);
});

test('diffFilename names both scans and the network, base first', () => {
  assert.equal(
    diffFilename({ id: 12 }, { id: 15, cidr: '192.168.1.0/24' }, 'csv'),
    'lanscope_diff_12-vs-15_192-168-1-0-24.csv',
  );
});

test('the classification round-trips through a real database scan shape', () => {
  const CIDR = '10.7.7.0/24';
  const s1 = db.startScan(CIDR);
  db.finishScan(s1, [
    { ip: '10.7.7.5', status: 'up', hostname: 'printer' },
    { ip: '10.7.7.6', status: 'up' },
  ]);
  const s2 = db.startScan(CIDR);
  db.finishScan(s2, [
    { ip: '10.7.7.5', status: 'up', hostname: 'printer-lab' },
    { ip: '10.7.7.7', status: 'up' },
  ]);
  const d = diffScans(db.getScan(s1), db.getScan(s2));
  assert.deepEqual(d.appeared.map((h) => h.ip), ['10.7.7.7']);
  assert.deepEqual(d.disappeared.map((h) => h.ip), ['10.7.7.6']);
  assert.deepEqual(d.changed.map((c) => c.reasons), [['hostname']]);
  const csv = diffToCsv(d);
  assert.match(csv, /changed,10\.7\.7\.5/);
});
