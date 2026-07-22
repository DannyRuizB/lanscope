'use strict';

// getLatencySparks needs a real SQLite — point DB_PATH at a throwaway file
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

// Each test uses its own CIDR so scan sets never interfere across tests.
function makeScan(cidr, hosts) {
  const id = db.startScan(cidr, null);
  db.finishScan(id, hosts);
  return id;
}

test('series align on one shared scan axis, absences stay null', () => {
  const cidr = '10.90.1.0/24';
  // Host .1 answers in all three scans; .2 skips the middle one.
  makeScan(cidr, [
    { ip: '10.90.1.1', status: 'up', latency_ms: 1.0 },
    { ip: '10.90.1.2', status: 'up', latency_ms: 5.0 },
  ]);
  makeScan(cidr, [{ ip: '10.90.1.1', status: 'up', latency_ms: 2.0 }]);
  makeScan(cidr, [
    { ip: '10.90.1.1', status: 'up', latency_ms: 3.0 },
    { ip: '10.90.1.2', status: 'up', latency_ms: 7.0 },
  ]);

  const { scan_ids, sparks } = db.getLatencySparks(cidr);
  assert.equal(scan_ids.length, 3);
  assert.deepEqual(sparks['10.90.1.1'], [1.0, 2.0, 3.0]);
  assert.deepEqual(sparks['10.90.1.2'], [5.0, null, 7.0]);
});

test('a present but untimed host is null, not zero', () => {
  const cidr = '10.90.2.0/24';
  makeScan(cidr, [{ ip: '10.90.2.9', status: 'up' }]); // e.g. a -Pn scan
  makeScan(cidr, [{ ip: '10.90.2.9', status: 'up', latency_ms: 4.2 }]);

  const { sparks } = db.getLatencySparks(cidr);
  assert.deepEqual(sparks['10.90.2.9'], [null, 4.2]);
});

test('the window keeps only the newest N scans', () => {
  const cidr = '10.90.3.0/24';
  for (let i = 1; i <= 25; i++) {
    makeScan(cidr, [{ ip: '10.90.3.5', status: 'up', latency_ms: i }]);
  }
  const { scan_ids, sparks } = db.getLatencySparks(cidr); // default limit 20
  assert.equal(scan_ids.length, 20);
  assert.equal(sparks['10.90.3.5'].length, 20);
  // Oldest → newest: the window is the LAST 20 measurements (6..25).
  assert.equal(sparks['10.90.3.5'][0], 6);
  assert.equal(sparks['10.90.3.5'][19], 25);

  const short = db.getLatencySparks(cidr, 5);
  assert.deepEqual(short.sparks['10.90.3.5'], [21, 22, 23, 24, 25]);
});

test('a network with no scans yields an empty axis and no sparks', () => {
  const { scan_ids, sparks } = db.getLatencySparks('10.90.4.0/24');
  assert.deepEqual(scan_ids, []);
  assert.deepEqual(sparks, {});
});
