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
