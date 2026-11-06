'use strict';

// v1.58.0 — GET /healthz, the probe behind the image's HEALTHCHECK. It must
// answer without a credential (Docker has none to present), say only ok /
// unavailable, and turn a database that cannot be read into a 503 - so that
// `docker ps` stops calling a server healthy just because it is listening.
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { healthz } = require('../src/health');

function fakeRes() {
  const res = { statusCode: 200, headers: {}, body: undefined };
  res.status = (c) => { res.statusCode = c; return res; };
  res.set = (k, v) => { res.headers[k.toLowerCase()] = v; return res; };
  res.json = (b) => { res.body = b; return res; };
  return res;
}

test('healthz: ok when the ping answers, no-store', () => {
  const res = fakeRes();
  healthz(() => 3)({}, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { status: 'ok' });
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('healthz: 503 when the database cannot be read, and the error stays in the log', () => {
  const logged = [];
  const res = fakeRes();
  healthz(() => { throw new Error('SQLITE_NOTADB: file is not a database at /var/lib/lanscope/lanscope.db'); },
    (m) => logged.push(m))({}, res);
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.body, { status: 'unavailable' }, 'nothing about the failure in the answer');
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(logged.length, 1);
  assert.match(logged[0], /health check failed: SQLITE_NOTADB/);
});

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

test('GET /healthz on the real server: open with auth on, the API stays locked', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-healthz-'));
  const port = await freePort();
  const env = { ...process.env, DB_PATH: path.join(dir, 'lanscope.db'), PORT: String(port),
    AUTH_USER: 'ops', AUTH_PASS: 'a-long-enough-password' };
  for (const k of ['DEMO_MODE', 'NODE_TEST_CONTEXT']) delete env[k];
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  try {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`server did not start:\n${out}`)), 15000);
      const check = setInterval(() => {
        if (out.includes('LanScope listening')) { clearTimeout(t); clearInterval(check); resolve(); }
      }, 50);
      child.once('exit', () => { clearTimeout(t); clearInterval(check); reject(new Error(`server exited:\n${out}`)); });
    });
    const h = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(h.status, 200);
    assert.deepEqual(await h.json(), { status: 'ok' });
    assert.equal(h.headers.get('cache-control'), 'no-store');
    assert.equal(h.headers.get('www-authenticate'), null, 'no credential asked for');
    const api = await fetch(`http://127.0.0.1:${port}/api/scans`);
    assert.equal(api.status, 401, 'the probe opens /healthz, not the API');
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => child.once('exit', r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
