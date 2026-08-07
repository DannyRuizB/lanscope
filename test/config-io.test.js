'use strict';

// Config export/import (v1.23.0) needs a real SQLite — point DB_PATH at a
// throwaway file BEFORE requiring db (the module opens the database at
// import time; the test runner gives each test file its own process).
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
const { validateConfigDoc } = require('../src/http-validators');
const { validateCidr, validateIpv4 } = require('../src/scanner');
const scheduler = require('../src/scheduler');

const DEPS = {
  validateCidr,
  validateIpv4,
  validateScanOptions: scheduler.validateScheduleScanOptions,
  alertTypes: db.ALERT_TYPES,
};

function validDoc() {
  return {
    lanscope_config: 1,
    exported_at: 1785000000000,
    labels: [
      { cidr: '192.168.7.0/24', ip: '192.168.7.10', label: '  NAS  ', notes: null },
    ],
    mutes: [
      { cidr: '192.168.7.0/24', ip: '192.168.7.20', types: ['high_latency'], expires_at: null },
      { cidr: '192.168.7.0/24', ip: '192.168.7.21', types: null, expires_at: null },
    ],
    schedules: [
      { name: 'Nightly sweep', cidr: '192.168.7.0/24', cron_expr: '0 3 * * *', enabled: true, scan_options: null, keep_last: 24, latency_alert_ms: null },
    ],
    channels: [
      { name: 'Ops webhook', type: 'webhook', config: { url: 'https://example.com/hook' }, events: ['scan_done'], enabled: false },
    ],
  };
}

test('validateConfigDoc normalizes a valid document', () => {
  const v = validateConfigDoc(validDoc(), DEPS);
  assert.ok(!v.error, v.error);
  assert.equal(v.value.labels[0].label, 'NAS', 'label text is trimmed');
  assert.deepEqual(v.value.mutes[0].types, ['high_latency']);
  assert.equal(v.value.schedules[0].keep_last, 24);
  // The webhook format defaults exactly like the live endpoint.
  assert.equal(v.value.channels[0].config.format, 'generic');
  assert.equal(v.value.channels[0].enabled, false);
});

test('validateConfigDoc canonicalizes a full types set to null, same as the live endpoint', () => {
  const doc = validDoc();
  doc.mutes = [{ cidr: '192.168.7.0/24', ip: '192.168.7.22', types: [...db.ALERT_TYPES] }];
  const v = validateConfigDoc(doc, DEPS);
  assert.ok(!v.error, v.error);
  assert.equal(v.value.mutes[0].types, null);
});

test('validateConfigDoc rejects bad documents and names the offending item', () => {
  assert.match(validateConfigDoc({}, DEPS).error, /lanscope_config/);
  assert.match(validateConfigDoc(null, DEPS).error, /config export object/);

  const badCidr = validDoc();
  badCidr.labels[0].cidr = 'not-a-cidr';
  assert.match(validateConfigDoc(badCidr, DEPS).error, /labels\[0\]/);

  const badType = validDoc();
  badType.mutes[0].types = ['no_such_type'];
  assert.match(validateConfigDoc(badType, DEPS).error, /mutes\[0\].*no_such_type/);

  const badCron = validDoc();
  badCron.schedules[0].cron_expr = 'every full moon';
  assert.match(validateConfigDoc(badCron, DEPS).error, /schedules\[0\]/);

  const badUrl = validDoc();
  badUrl.channels[0].config = { url: 'ftp://nope' };
  assert.match(validateConfigDoc(badUrl, DEPS).error, /channels\[0\]/);

  const notArray = validDoc();
  notArray.mutes = { oops: true };
  assert.match(validateConfigDoc(notArray, DEPS).error, /mutes must be an array/);
});

test('a past expires_at is legal in a backup — the lazy purge retires it on first read', () => {
  const doc = validDoc();
  doc.mutes = [{ cidr: '192.168.7.0/24', ip: '192.168.7.30', types: null, expires_at: 1000 }];
  const v = validateConfigDoc(doc, DEPS);
  assert.ok(!v.error, v.error);
  db.importConfig({ labels: [], mutes: v.value.mutes, schedules: [], channels: [] });
  assert.ok(!db.getMutedIps('192.168.7.0/24').has('192.168.7.30'));
  assert.equal(db.listAllMutes().filter((m) => m.ip === '192.168.7.30').length, 0);
});

test('importConfig roundtrip: everything lands, and re-import breeds no duplicates', () => {
  const v = validateConfigDoc(validDoc(), DEPS);
  assert.ok(!v.error, v.error);

  const first = db.importConfig(v.value);
  assert.deepEqual(first.imported, { labels: 1, mutes: 2, schedules: 1, channels: 1 });
  assert.deepEqual(first.skipped, { schedules: [], channels: [] });

  assert.equal(db.listAllLabels().find((l) => l.ip === '192.168.7.10').label, 'NAS');
  assert.ok(db.getMutedIps('192.168.7.0/24').has('192.168.7.20'));
  assert.equal(db.listSchedules().filter((s) => s.name === 'Nightly sweep').length, 1);
  assert.equal(db.listChannels().filter((c) => c.name === 'Ops webhook').length, 1);

  // Re-importing the same backup: labels/mutes upsert in place, schedules
  // and channels are skipped by name — nothing is duplicated.
  const again = db.importConfig(v.value);
  assert.deepEqual(again.imported, { labels: 1, mutes: 2, schedules: 0, channels: 0 });
  assert.deepEqual(again.skipped, { schedules: ['Nightly sweep'], channels: ['Ops webhook'] });
  assert.equal(db.listSchedules().filter((s) => s.name === 'Nightly sweep').length, 1);
  assert.equal(db.listChannels().filter((c) => c.name === 'Ops webhook').length, 1);
});

test('imported channel keeps its enabled=false and its events', () => {
  const chan = db.listChannels().find((c) => c.name === 'Ops webhook');
  assert.ok(chan, 'channel exists from the roundtrip test');
  assert.equal(!!chan.enabled, false);
  assert.deepEqual(chan.events, ['scan_done']);
  assert.equal(chan.config.format, 'generic');
});

// --- dry run (v1.24.0) ------------------------------------------------------
// The tests above left the roundtrip's rows in place, which is exactly the
// state a dry run has to describe honestly: same names again = updates and
// skips, not a fresh install.

test('a dry run writes nothing and reports the same counts the real import would', () => {
  const v = validateConfigDoc(validDoc(), DEPS);
  assert.ok(!v.error, v.error);

  const before = {
    labels: db.listAllLabels().length,
    mutes: db.listAllMutes().length,
    schedules: db.listSchedules().length,
    channels: db.listChannels().length,
  };

  const dry = db.importConfig(v.value, { dryRun: true });
  assert.equal(dry.dry_run, true);
  assert.deepEqual(dry.imported, { labels: 1, mutes: 2, schedules: 0, channels: 0 });
  assert.deepEqual(dry.skipped, { schedules: ['Nightly sweep'], channels: ['Ops webhook'] });

  // Nothing moved on disk — the rollback is the whole point.
  assert.equal(db.listAllLabels().length, before.labels);
  assert.equal(db.listAllMutes().length, before.mutes);
  assert.equal(db.listSchedules().length, before.schedules);
  assert.equal(db.listChannels().length, before.channels);
});

test('the plan separates new rows from the ones an upsert would overwrite', () => {
  const doc = validDoc();
  // 192.168.7.10 already carries a label from the roundtrip test; this IP does
  // not — so one gets overwritten and one is created.
  doc.labels.push({ cidr: '192.168.7.0/24', ip: '192.168.7.77', label: 'Printer', notes: null });
  const v = validateConfigDoc(doc, DEPS);
  assert.ok(!v.error, v.error);

  const dry = db.importConfig(v.value, { dryRun: true });
  assert.equal(dry.plan.labels.created, 1);
  assert.deepEqual(dry.plan.labels.updated, ['192.168.7.10']);
  // Both roundtrip mutes exist already, so both would be overwritten.
  assert.equal(dry.plan.mutes.created, 0);
  assert.equal(dry.plan.mutes.updated.length, 2);

  // And the dry run really was dry: the new IP never landed.
  assert.equal(db.listAllLabels().filter((l) => l.ip === '192.168.7.77').length, 0);
});

test('a real import after a dry run lands exactly what the plan promised', () => {
  const doc = validDoc();
  doc.labels.push({ cidr: '192.168.7.0/24', ip: '192.168.7.77', label: 'Printer', notes: null });
  const v = validateConfigDoc(doc, DEPS);
  const dry = db.importConfig(v.value, { dryRun: true });
  const real = db.importConfig(v.value);

  assert.equal(real.dry_run, false);
  assert.deepEqual(real.imported, dry.imported);
  assert.deepEqual(real.skipped, dry.skipped);
  assert.deepEqual(real.plan, dry.plan);
  assert.equal(db.listAllLabels().find((l) => l.ip === '192.168.7.77').label, 'Printer');
});

test('a dry run of an invalid-but-parsed doc still rolls back partial work', () => {
  // A schedule whose cron the validator accepts but createSchedule rejects is
  // hard to fake; instead prove the rollback survives an exception thrown
  // mid-transaction by handing the real import a doc that dies halfway.
  const doc = validDoc();
  doc.labels = [
    { cidr: '192.168.7.0/24', ip: '192.168.7.88', label: 'First', notes: null },
    // A cidr the DB layer will choke on (NOT NULL violation) — validation is
    // bypassed here on purpose to exercise the transaction, not the validator.
    { cidr: null, ip: '192.168.7.89', label: 'Second', notes: null },
  ];
  assert.throws(() => db.importConfig({ labels: doc.labels, mutes: [], schedules: [], channels: [] }));
  // All-or-nothing: the first label must NOT be there.
  assert.equal(db.listAllLabels().filter((l) => l.ip === '192.168.7.88').length, 0);
});

// --- selective export composes with import (v1.26.0) ------------------------

test('a labels-only document restores labels and cannot touch anything else', () => {
  // Exactly what GET /api/config/export?sections=labels produces: the other
  // section keys are ABSENT, not empty — and the import side must read that
  // as "nothing to restore here".
  const doc = {
    lanscope_config: 1,
    exported_at: 1785000000000,
    labels: [
      { cidr: '10.9.0.0/24', ip: '10.9.0.5', label: 'Camera', notes: null },
    ],
  };
  const before = {
    schedules: db.listSchedules().length,
    channels: db.listChannels().length,
    mutes: db.listAllMutes().length,
  };
  const v = validateConfigDoc(doc, DEPS);
  assert.ok(!v.error, v.error);
  const r = db.importConfig(v.value);
  assert.equal(r.imported.labels, 1);
  assert.deepEqual(
    { schedules: db.listSchedules().length, channels: db.listChannels().length, mutes: db.listAllMutes().length },
    before,
    'sections the backup does not carry stay untouched',
  );
  assert.equal(db.listAllLabels().find((l) => l.ip === '10.9.0.5').label, 'Camera');
});

// --- selective import (v1.27.0) --------------------------------------------
// The endpoint filters the validated document down to the requested sections
// before handing it to importConfig (?sections=labels zeroes the rest). These
// prove the composition the endpoint relies on: a section reduced to [] is
// left untouched, whatever the source document also carried.

test('a full document scoped to labels imports only labels, leaving the rest', () => {
  // A complete backup — labels, mutes, a schedule and a channel with FRESH
  // names so they WOULD import if not scoped out.
  const full = {
    lanscope_config: 1,
    exported_at: 1785000000000,
    labels: [{ cidr: '10.27.0.0/24', ip: '10.27.0.5', label: 'ScopedCam', notes: null }],
    mutes: [{ cidr: '10.27.0.0/24', ip: '10.27.0.9', types: null, expires_at: null }],
    schedules: [{ name: 'v127 nightly', cidr: '10.27.0.0/24', cron_expr: '0 4 * * *', enabled: true, scan_options: null, keep_last: null, latency_alert_ms: null }],
    channels: [{ name: 'v127 hook', type: 'webhook', config: { url: 'https://example.com/v127' }, events: ['scan_done'], enabled: false }],
  };
  const v = validateConfigDoc(full, DEPS);
  assert.ok(!v.error, v.error);
  // What the endpoint does for ?sections=labels: keep labels, zero the rest.
  const scoped = { ...v.value, mutes: [], schedules: [], channels: [] };
  const schedBefore = db.listSchedules().length;
  const chanBefore = db.listChannels().length;
  const muteBefore = db.listAllMutes().length;
  const r = db.importConfig(scoped);
  assert.equal(r.imported.labels, 1);
  assert.equal(r.imported.mutes, 0);
  assert.equal(r.imported.schedules, 0);
  assert.equal(r.imported.channels, 0);
  assert.equal(db.listSchedules().length, schedBefore, 'the schedule in the doc was scoped out');
  assert.equal(db.listChannels().length, chanBefore, 'the channel in the doc was scoped out');
  assert.equal(db.listAllMutes().length, muteBefore, 'the mute in the doc was scoped out');
  assert.equal(db.listAllLabels().find((l) => l.ip === '10.27.0.5').label, 'ScopedCam');
});
