'use strict';

// Alert mutes (v1.20.0) need a real SQLite — point DB_PATH at a throwaway
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
} = require('../src/alerts');

// Each test gets its own CIDR so scans/baselines/mutes never bleed across
// tests.
let n = 0;
let CIDR;
beforeEach(() => {
  n += 1;
  CIDR = `10.60.${n}.0/24`;
  delete process.env.LATENCY_ALERT_MS;
  delete process.env.SENSITIVE_PORTS;
});

function doneScan(hosts) {
  const id = db.startScan(CIDR);
  db.finishScan(id, hosts);
  return id;
}

test('setMute/clearMute: idempotent upsert keyed by (cidr, ip)', () => {
  const ip = `10.60.${n}.9`;
  assert.equal(db.listMutes(CIDR).length, 0);
  const row = db.setMute(CIDR, ip);
  assert.equal(row.ip, ip);
  db.setMute(CIDR, ip); // flipping it twice must not create two rows
  assert.equal(db.listMutes(CIDR).length, 1);
  assert.ok(db.getMutedIps(CIDR).has(ip));
  assert.equal(db.clearMute(CIDR, ip), null);
  db.clearMute(CIDR, ip); // clearing an absent mute is a quiet no-op
  assert.equal(db.listMutes(CIDR).length, 0);
});

test('mutes are scoped to their network — the same ip elsewhere still alerts', () => {
  const ip = `10.60.${n}.9`;
  db.setMute(CIDR, ip);
  assert.ok(!db.getMutedIps('192.168.99.0/24').has(ip));
});

test('a muted host raises no high_latency alert; its neighbours still do', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const slow1 = `10.60.${n}.11`;
  const slow2 = `10.60.${n}.12`;
  db.setMute(CIDR, slow1);
  const id = doneScan([
    { ip: slow1, status: 'up', latency_ms: 300 },
    { ip: slow2, status: 'up', latency_ms: 300 },
  ]);
  const alerts = detectAlertsForScan(id);
  const ips = alerts.map((a) => a.payload.ip);
  assert.deepEqual(ips, [slow2], 'only the unmuted slow host alerts');
});

test('baseline drift is suppressed for a muted host — disappeared included (host_id is null there)', () => {
  const stay = `10.60.${n}.20`;
  const vanish = `10.60.${n}.21`;
  const appear = `10.60.${n}.22`;
  const baselineId = doneScan([
    { ip: stay, status: 'up' },
    { ip: vanish, status: 'up' },
  ]);
  db.setBaseline(baselineId);
  db.setMute(CIDR, vanish);
  db.setMute(CIDR, appear);
  const id = doneScan([
    { ip: stay, status: 'up' },
    { ip: appear, status: 'up' },
  ]);
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.length, 0, 'both drift alerts suppressed by their mutes');

  // Control: the same scan shape without mutes raises both.
  db.clearMute(CIDR, vanish);
  db.clearMute(CIDR, appear);
  const id2 = doneScan([
    { ip: stay, status: 'up' },
    { ip: appear, status: 'up' },
  ]);
  const types = detectAlertsForScan(id2).map((a) => a.type).sort();
  assert.deepEqual(types, ['appeared', 'disappeared']);
});

test('the sensitive_port scan pass skips a muted host', () => {
  process.env.SENSITIVE_PORTS = '23,445';
  const ip = `10.60.${n}.30`;
  db.setMute(CIDR, ip);
  const id = doneScan([
    {
      ip,
      status: 'up',
      portscanned_at: Date.now(),
      ports: [{ port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' }],
    },
  ]);
  assert.equal(detectAlertsForScan(id).length, 0);
});

test('the live portscan hook respects the mute — and fires again once unmuted', () => {
  process.env.SENSITIVE_PORTS = '23,445';
  const ip = `10.60.${n}.40`;
  const id = doneScan([{ ip, status: 'up' }]);
  const scan = db.getScan(id);
  const hostId = scan.hosts.find((h) => h.ip === ip).id;
  db.saveHostPorts(hostId, [
    { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
  ]);

  db.setMute(CIDR, ip);
  assert.equal(detectSensitivePortsForHost(hostId).length, 0, 'muted: nothing raised');

  db.clearMute(CIDR, ip);
  const raised = detectSensitivePortsForHost(hostId);
  assert.equal(raised.length, 1, 'unmuted: the exposure is news again');
  assert.equal(raised[0].type, 'sensitive_port');
});

test('muting does not touch alerts that already exist', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.50`;
  const id = doneScan([{ ip, status: 'up', latency_ms: 300 }]);
  const before = detectAlertsForScan(id);
  assert.equal(before.length, 1);
  db.setMute(CIDR, ip);
  const still = db.listAlerts({ cidr: CIDR });
  assert.equal(still.length, 1, 'the pre-existing alert stays until acknowledged');
});

// ----- v1.21.0: type-scoped mutes --------------------------------------------

test('setMute stores a type scope, re-muting updates it in place', () => {
  const ip = `10.60.${n}.60`;
  const scoped = db.setMute(CIDR, ip, ['high_latency']);
  assert.deepEqual(scoped.types, ['high_latency']);
  const widened = db.setMute(CIDR, ip); // re-mute with no scope = everything
  assert.equal(widened.types, null);
  const narrowed = db.setMute(CIDR, ip, ['sensitive_port', 'appeared']);
  assert.deepEqual(narrowed.types, ['appeared', 'sensitive_port'], 'stored sorted');
  assert.equal(db.listMutes(CIDR).length, 1, 'three saves, still one row');
  // Presence stays scope-blind: a partially muted host still "has a mute".
  assert.ok(db.getMutedIps(CIDR).has(ip));
});

test('a latency-only mute silences high_latency and nothing else', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.61`;
  const baselineId = doneScan([
    { ip, status: 'up', latency_ms: 1, hostname: 'printer.lan' },
  ]);
  db.setBaseline(baselineId);
  db.setMute(CIDR, ip, ['high_latency']);
  // The host comes back slow AND with a different hostname: the latency
  // finding dies at the scope, the drift one sails through. (Both scans
  // carry a hostname — the detector only judges a rename, not a naming.)
  const id = doneScan([
    { ip, status: 'up', latency_ms: 300, hostname: 'renamed.lan' },
  ]);
  const types = detectAlertsForScan(id).map((a) => a.type);
  assert.deepEqual(types, ['changed_hostname'], 'drift alerts, latency muted');
});

test('a disappeared-scoped mute lets an appearance elsewhere in scope through', () => {
  const vanish = `10.60.${n}.62`;
  const stay = `10.60.${n}.63`;
  const baselineId = doneScan([
    { ip: vanish, status: 'up' },
    { ip: stay, status: 'up' },
  ]);
  db.setBaseline(baselineId);
  // Scoped to 'appeared' only: the host vanishing must STILL raise
  // disappeared (host_id is null there — the scope check rides payload.ip).
  db.setMute(CIDR, vanish, ['appeared']);
  const id = doneScan([{ ip: stay, status: 'up' }]);
  const types = detectAlertsForScan(id).map((a) => a.type);
  assert.deepEqual(types, ['disappeared'], 'the mute scope does not cover it');
});

test('the live portscan hook honours the scope: latency-only mute keeps exposure alive', () => {
  process.env.SENSITIVE_PORTS = '23,445';
  const ip = `10.60.${n}.64`;
  const id = doneScan([{ ip, status: 'up' }]);
  const hostId = db.getScan(id).hosts.find((h) => h.ip === ip).id;
  db.saveHostPorts(hostId, [
    { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
  ]);

  db.setMute(CIDR, ip, ['high_latency']);
  const raised = detectSensitivePortsForHost(hostId);
  assert.equal(raised.length, 1, 'exposure is outside the mute scope');
  db.ackAlert(raised[0].id);

  db.setMute(CIDR, ip, ['sensitive_port']);
  assert.equal(
    detectSensitivePortsForHost(hostId).length,
    0,
    'an exposure-scoped mute suppresses it',
  );
});

// ----- v1.22.0: mute expiry ("snooze") -------------------------------------

test('a snoozed mute suppresses while live and round-trips its deadline', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.70`;
  const until = Date.now() + 3600_000;
  const row = db.setMute(CIDR, ip, null, until);
  assert.equal(row.expires_at, until, 'the stored deadline comes back verbatim');
  assert.ok(db.getMutedIps(CIDR).has(ip), 'live snooze reads as muted');
  const id = doneScan([{ ip, status: 'up', latency_ms: 300 }]);
  assert.equal(detectAlertsForScan(id).length, 0, 'live snooze suppresses');
});

test('an expired snooze re-arms alerting by itself and is purged from the table', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.71`;
  db.setMute(CIDR, ip, null, Date.now() - 1000); // already past
  const id = doneScan([{ ip, status: 'up', latency_ms: 300 }]);
  const alerts = detectAlertsForScan(id);
  assert.equal(alerts.length, 1, 'the expired mute no longer suppresses');
  assert.equal(alerts[0].type, 'high_latency');
  assert.equal(db.listMutes(CIDR).length, 0, 'the dead row is gone, not lingering');
});

test('a permanent mute (expires_at null) keeps the pre-v1.22 behaviour forever', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.72`;
  const row = db.setMute(CIDR, ip); // no types, no expiry — the v1.20 call shape
  assert.equal(row.expires_at, null);
  const id = doneScan([{ ip, status: 'up', latency_ms: 300 }]);
  assert.equal(detectAlertsForScan(id).length, 0);
});

test('re-muting re-arms or clears the clock: the upsert takes the new expiry', () => {
  const ip = `10.60.${n}.73`;
  const e1 = Date.now() + 3600_000;
  assert.equal(db.setMute(CIDR, ip, null, e1).expires_at, e1);
  const e2 = Date.now() + 7200_000;
  assert.equal(db.setMute(CIDR, ip, null, e2).expires_at, e2, 're-snooze re-arms');
  assert.equal(db.setMute(CIDR, ip).expires_at, null, 'saving forever clears the deadline');
  assert.equal(db.listMutes(CIDR).length, 1, 'still one row through it all');
});

test('a snoozed scoped mute expires as one unit — scope does not outlive the clock', () => {
  process.env.LATENCY_ALERT_MS = '50';
  const ip = `10.60.${n}.74`;
  db.setMute(CIDR, ip, ['high_latency'], Date.now() - 1000);
  const id = doneScan([{ ip, status: 'up', latency_ms: 300 }]);
  assert.equal(detectAlertsForScan(id).length, 1, 'expired scope suppresses nothing');
});
