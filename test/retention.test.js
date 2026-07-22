'use strict';

// pruneScheduleScans needs a real SQLite — point DB_PATH at a throwaway file
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

// Every test gets its own schedule + CIDR so scan sets (and the per-CIDR
// baseline) never interfere across tests.
let seq = 0;
function makeSchedule(cidr, keepLast) {
  return db.createSchedule({
    name: `retention fixture ${++seq}`,
    cidr,
    cron_expr: '0 * * * *',
    enabled: false,
    scan_options: null,
    keep_last: keepLast,
  });
}

function makeScan(cidr, scheduleId) {
  const id = db.startScan(cidr, scheduleId);
  db.finishScan(id, [{ ip: cidr.replace(/0\/24$/, '7'), status: 'up' }]);
  return id;
}

test('prune keeps the newest N scans and deletes the rest', () => {
  const cidr = '10.80.1.0/24';
  const sched = makeSchedule(cidr, 2);
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push(makeScan(cidr, sched.id));

  const pruned = db.pruneScheduleScans(sched.id, sched.keep_last);

  assert.equal(pruned, 3);
  assert.ok(db.getScan(ids[4]), 'newest scan survives');
  assert.ok(db.getScan(ids[3]), 'second-newest scan survives');
  assert.ok(!db.getScan(ids[2]), 'older scans are gone');
  assert.ok(!db.getScan(ids[0]), 'oldest scan is gone');
});

test('the declared baseline is never pruned, even outside the window', () => {
  const cidr = '10.80.2.0/24';
  const sched = makeSchedule(cidr, 1);
  const oldest = makeScan(cidr, sched.id);
  const middle = makeScan(cidr, sched.id);
  const newest = makeScan(cidr, sched.id);
  db.setBaseline(oldest);

  const pruned = db.pruneScheduleScans(sched.id, sched.keep_last);

  assert.equal(pruned, 1, 'only the unprotected middle scan goes');
  assert.ok(db.getScan(oldest), 'baseline scan survives outside the window');
  assert.ok(!db.getScan(middle));
  assert.ok(db.getScan(newest));
});

test('a pending alert protects its scan; an acked one does not', () => {
  const cidr = '10.80.3.0/24';
  const sched = makeSchedule(cidr, 1);
  const withPending = makeScan(cidr, sched.id);
  const withAcked = makeScan(cidr, sched.id);
  const newest = makeScan(cidr, sched.id);
  db.createAlert({ scan_id: withPending, cidr, type: 'appeared', payload: {} });
  const acked = db.createAlert({ scan_id: withAcked, cidr, type: 'appeared', payload: {} });
  db.ackAlert(acked.id);

  const pruned = db.pruneScheduleScans(sched.id, sched.keep_last);

  assert.equal(pruned, 1);
  assert.ok(db.getScan(withPending), 'scan with an unacknowledged alert survives');
  assert.ok(!db.getScan(withAcked), 'acked alerts are triaged — their scan is prunable');
  assert.ok(db.getScan(newest));
});

test('manual scans and other schedules are untouched', () => {
  const cidr = '10.80.4.0/24';
  const schedA = makeSchedule(cidr, 1);
  const schedB = makeSchedule(cidr, null);
  const aOld = makeScan(cidr, schedA.id);
  const aNew = makeScan(cidr, schedA.id);
  const manual = makeScan(cidr, null);
  const bOld = makeScan(cidr, schedB.id);

  const pruned = db.pruneScheduleScans(schedA.id, schedA.keep_last);

  assert.equal(pruned, 1);
  assert.ok(!db.getScan(aOld), "schedule A's old scan is gone");
  assert.ok(db.getScan(aNew));
  assert.ok(db.getScan(manual), 'manual scans never expire');
  assert.ok(db.getScan(bOld), "schedule B's scans are not A's business");
});

test('no keep_last means no pruning at all', () => {
  const cidr = '10.80.5.0/24';
  const sched = makeSchedule(cidr, null);
  const ids = [makeScan(cidr, sched.id), makeScan(cidr, sched.id)];

  assert.equal(db.pruneScheduleScans(sched.id, sched.keep_last), 0);
  assert.equal(db.pruneScheduleScans(sched.id, 0), 0);
  assert.equal(db.pruneScheduleScans(sched.id, 1.5), 0);
  assert.ok(db.getScan(ids[0]));
  assert.ok(db.getScan(ids[1]));
});
