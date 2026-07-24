'use strict';

// The notifier module pulls in db at import time — point DB_PATH at a
// throwaway file BEFORE requiring it (same pattern as alerts.test.js).
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
process.env.DB_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-test-')),
  'test.db',
);

const http = require('node:http');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { sendToChannel } = require('../src/notifier');

// A real local HTTP receiver instead of poking at internals: what lands on
// the wire is the contract downstream consumers parse.
let server;
let baseUrl;
let last; // { headers, body } of the most recent delivery

before(async () => {
  server = http.createServer((req, res) => {
    let chunks = '';
    req.on('data', (c) => (chunks += c));
    req.on('end', () => {
      last = { headers: req.headers, body: chunks };
      res.writeHead(200).end('ok');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

const HIGH_LATENCY_CTX = {
  scan: { id: 42, cidr: '10.0.0.0/24', host_count: 13, started_at: 1700000000000 },
  total: 2,
  threshold_ms: 100,
  slow_hosts: [
    { ip: '10.0.0.7', hostname: 'cam-7.lan', latency_ms: 250 },
    { ip: '10.0.0.9', hostname: null, latency_ms: 120 },
  ],
};

test('high_latency generic webhook carries threshold, offenders and summary', async () => {
  await sendToChannel(
    { type: 'webhook', config: { url: `${baseUrl}/hook`, format: 'generic' } },
    'high_latency',
    HIGH_LATENCY_CTX,
  );
  const body = JSON.parse(last.body);
  assert.equal(body.event, 'high_latency');
  assert.equal(
    body.summary,
    'High latency on 10.0.0.0/24: 2 hosts at or above 100 ms (worst: 10.0.0.7 at 250 ms)',
  );
  assert.equal(body.total, 2);
  assert.equal(body.threshold_ms, 100);
  assert.deepEqual(body.slow_hosts, HIGH_LATENCY_CTX.slow_hosts);
  // Not a divergence event: the baseline fields stay null, not absent.
  assert.equal(body.counts, null);
  assert.equal(body.baseline, null);
});

test('high_latency summary uses the singular for one host', async () => {
  await sendToChannel(
    { type: 'webhook', config: { url: `${baseUrl}/hook` } },
    'high_latency',
    {
      scan: { id: 1, cidr: '10.0.0.0/24', host_count: 3, started_at: 1 },
      total: 1,
      threshold_ms: 50,
      slow_hosts: [{ ip: '10.0.0.5', hostname: null, latency_ms: 51.5 }],
    },
  );
  const body = JSON.parse(last.body);
  assert.equal(
    body.summary,
    'High latency on 10.0.0.0/24: 1 host at or above 50 ms (worst: 10.0.0.5 at 51.5 ms)',
  );
});

test('high_latency ntfy delivery sets its own title, tag and priority', async () => {
  await sendToChannel(
    { type: 'ntfy', config: { topic: 'lanscope-test', server: baseUrl } },
    'high_latency',
    HIGH_LATENCY_CTX,
  );
  assert.equal(last.headers.title, 'High latency detected');
  assert.equal(last.headers.tags, 'hourglass');
  assert.equal(last.headers.priority, 'default');
  assert.match(last.body, /^High latency on 10\.0\.0\.0\/24: 2 hosts/);
});

test('baseline_diff payload keeps the stable shape (latency fields null)', async () => {
  await sendToChannel(
    { type: 'webhook', config: { url: `${baseUrl}/hook` } },
    'baseline_diff',
    {
      scan: { id: 7, cidr: '10.0.0.0/24', host_count: 9, started_at: 1 },
      total: 3,
      counts: { appeared: 2, changed_ports: 1 },
      baseline: { scan_id: 5, set_at: 1 },
    },
  );
  const body = JSON.parse(last.body);
  assert.equal(body.event, 'baseline_diff');
  assert.equal(body.threshold_ms, null);
  assert.equal(body.slow_hosts, null);
  assert.match(body.summary, /Baseline divergence on 10\.0\.0\.0\/24: 3 changes/);
});

// --- daily_digest (v1.15.0) -------------------------------------------------

const DIGEST_CTX = {
  window_hours: 24,
  digest: {
    cidrs: [
      { cidr: '10.0.0.0/24', scans: 3, alerts_new: { appeared: 2 }, alerts_new_total: 2, alerts_pending: 4 },
      { cidr: '192.168.1.0/24', scans: 1, alerts_new: {}, alerts_new_total: 0, alerts_pending: 0 },
    ],
    totals: { networks: 2, scans: 4, alerts_new: 2, alerts_pending: 4 },
  },
};

test('daily_digest generic webhook carries the roll-up and a summary', async () => {
  await sendToChannel(
    { type: 'webhook', config: { url: `${baseUrl}/hook`, format: 'generic' } },
    'daily_digest',
    DIGEST_CTX,
  );
  const body = JSON.parse(last.body);
  assert.equal(body.event, 'daily_digest');
  assert.equal(
    body.summary,
    'LanScope daily digest (last 24h): 4 scans across 2 networks, 2 new alerts, 4 still pending',
  );
  assert.equal(body.window_hours, 24);
  assert.equal(body.digest.totals.networks, 2);
  // Not a per-scan event: those fields stay null.
  assert.equal(body.scan, null);
  assert.equal(body.threshold_ms, null);
});

test('daily_digest says so plainly when nothing happened', async () => {
  await sendToChannel(
    { type: 'webhook', config: { url: `${baseUrl}/hook` } },
    'daily_digest',
    { window_hours: 12, digest: { cidrs: [], totals: { networks: 0, scans: 0, alerts_new: 0, alerts_pending: 0 } } },
  );
  assert.match(JSON.parse(last.body).summary, /no scans in the last 12h/);
});

test('daily_digest ntfy delivery is low-priority with its own tag', async () => {
  await sendToChannel(
    { type: 'ntfy', config: { topic: 'lanscope-test', server: baseUrl } },
    'daily_digest',
    DIGEST_CTX,
  );
  assert.equal(last.headers.title, 'LanScope daily digest');
  assert.equal(last.headers.tags, 'bar_chart');
  assert.equal(last.headers.priority, 'low');
});
