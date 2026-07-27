'use strict';

// pruneAckedAlerts needs a real SQLite — point DB_PATH at a throwaway file
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
const { alertRetentionDays } = require('../src/alerts');
const scheduler = require('../src/scheduler');

const DAY = 24 * 60 * 60 * 1000;

// Each fixture gets its own CIDR so scans never interfere across tests.
let seq = 0;
function makeScan() {
  const cidr = `10.90.${++seq}.0/24`;
  const id = db.startScan(cidr, null);
  db.finishScan(id, [{ ip: `10.90.${seq}.7`, status: 'up' }]);
  return { id, cidr };
}

function makeAlert(scan) {
  return db.createAlert({
    scan_id: scan.id,
    cidr: scan.cidr,
    type: 'appeared',
    payload: { ip: '10.90.0.7' },
  });
}

// ackAlert stamps acknowledged_at with Date.now() — rewind the clock around
// the call to plant an alert that was acked `daysAgo` days in the past.
function ackDaysAgo(alertId, daysAgo) {
  const realNow = Date.now;
  Date.now = () => realNow() - daysAgo * DAY;
  try {
    db.ackAlert(alertId);
  } finally {
    Date.now = realNow;
  }
}

test('purges acked alerts older than the cutoff, keeps recently acked ones', () => {
  const scan = makeScan();
  const oldAcked = makeAlert(scan);
  const freshAcked = makeAlert(scan);
  ackDaysAgo(oldAcked.id, 40);
  ackDaysAgo(freshAcked.id, 2);

  const purged = db.pruneAckedAlerts(Date.now() - 30 * DAY);

  assert.equal(purged, 1);
  assert.equal(db.getAlert(oldAcked.id), null);
  assert.ok(db.getAlert(freshAcked.id), 'an alert acked inside the window must survive');
});

test('never purges pending alerts, no matter how old', () => {
  // Sweep any acked leftovers from earlier tests first — this assertion is
  // about the pending alert alone.
  db.pruneAckedAlerts(Date.now() + 365 * DAY);
  const scan = makeScan();
  const pending = makeAlert(scan); // created now, but never acknowledged

  // Cutoff in the FUTURE: every acked alert would match — a pending one may not.
  const purged = db.pruneAckedAlerts(Date.now() + 365 * DAY);

  assert.equal(purged, 0);
  assert.ok(db.getAlert(pending.id), 'pending alerts are not retention candidates');
});

test('the clock runs from acknowledged_at, not created_at', () => {
  const scan = makeScan();
  // Created long ago...
  const realNow = Date.now;
  Date.now = () => realNow() - 100 * DAY;
  let alert;
  try {
    alert = makeAlert(scan);
  } finally {
    Date.now = realNow;
  }
  // ...but acked just now: with a 30-day window it must survive.
  db.ackAlert(alert.id);

  const purged = db.pruneAckedAlerts(Date.now() - 30 * DAY);

  assert.equal(purged, 0);
  assert.ok(db.getAlert(alert.id), 'retention counts from the ack, not the firing');
});

test('alertRetentionDays: strict parse — off unless a positive number', () => {
  const cases = [
    [undefined, null],
    ['', null],
    ['0', null],
    ['-5', null],
    ['abc', null],
    ['30', 30],
    [' 14 ', 14],
    ['0.5', 0.5],
  ];
  const saved = process.env.ALERT_RETENTION_DAYS;
  try {
    for (const [raw, expected] of cases) {
      if (raw === undefined) delete process.env.ALERT_RETENTION_DAYS;
      else process.env.ALERT_RETENTION_DAYS = raw;
      assert.equal(alertRetentionDays(), expected, `parse of ${JSON.stringify(raw)}`);
    }
  } finally {
    if (saved === undefined) delete process.env.ALERT_RETENTION_DAYS;
    else process.env.ALERT_RETENTION_DAYS = saved;
  }
});

test('scheduler.purgeAckedAlerts honours the env: purge on, no-op off', () => {
  const scan = makeScan();
  const oldAcked = makeAlert(scan);
  ackDaysAgo(oldAcked.id, 90);

  const saved = process.env.ALERT_RETENTION_DAYS;
  try {
    // Off (unset): nothing happens, however old the alert is.
    delete process.env.ALERT_RETENTION_DAYS;
    assert.equal(scheduler.purgeAckedAlerts(), 0);
    assert.ok(db.getAlert(oldAcked.id), 'without the env the history is untouched');

    // On: the same alert goes.
    process.env.ALERT_RETENTION_DAYS = '30';
    assert.equal(scheduler.purgeAckedAlerts(), 1);
    assert.equal(db.getAlert(oldAcked.id), null);
  } finally {
    if (saved === undefined) delete process.env.ALERT_RETENTION_DAYS;
    else process.env.ALERT_RETENTION_DAYS = saved;
  }
});
