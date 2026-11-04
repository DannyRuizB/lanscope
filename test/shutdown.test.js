'use strict';

// v1.57.0 — the server stops cleanly on SIGTERM / SIGINT. Up to 1.56.0 it had
// no handler: in the container node is PID 1, which gets no default action
// for SIGTERM, so `docker stop` waited 10 s and SIGKILLed it (exit 137); the
// database was never closed and lanscope.db-wal never folded back in. This
// starts the real server on a throwaway database, writes a row through the
// API, signals it, and checks that it exits 0 promptly and that the main
// database file now holds everything on its own.
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');

const SERVER = path.join(__dirname, '..', 'src', 'server.js');

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

function startServer(dbPath, port) {
  const env = { ...process.env, DB_PATH: dbPath, PORT: String(port) };
  for (const k of ['AUTH_USER', 'AUTH_PASS', 'DEMO_MODE', 'NODE_TEST_CONTEXT']) delete env[k];
  const child = spawn(process.execPath, [SERVER], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal, out })));
  const listening = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start:\n${out}`)), 15000);
    const onData = (d) => {
      out += d;
      if (out.includes('LanScope listening')) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', (d) => { out += d; });
    child.once('exit', () => {
      clearTimeout(timer);
      reject(new Error(`server exited before listening:\n${out}`));
    });
  });
  return { child, listening, exited };
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`${signal}: exit 0, and lanscope.db alone holds the data`, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-stop-'));
    const dbPath = path.join(dir, 'lanscope.db');
    const port = await freePort();
    const { child, listening, exited } = startServer(dbPath, port);
    await listening;

    const put = await fetch(`http://127.0.0.1:${port}/api/labels`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ cidr: '192.168.50.0/24', ip: '192.168.50.7', label: `before ${signal}` }),
    });
    assert.equal(put.status, 200);
    // While it runs, the write-ahead log is where the data is.
    assert.ok(fs.statSync(`${dbPath}-wal`).size > 0);

    const t0 = Date.now();
    child.kill(signal);
    const { code, signal: killedBy, out } = await exited;
    assert.equal(killedBy, null, `killed by ${killedBy}, not a clean exit:\n${out}`);
    assert.equal(code, 0, out);
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms to stop`);
    assert.match(out, new RegExp(`\\[lanscope\\] ${signal}: closing the database`));

    // Checkpointed and removed: the main file is the whole database again.
    assert.equal(fs.existsSync(`${dbPath}-wal`), false);
    assert.equal(fs.existsSync(`${dbPath}-shm`), false);
    const copy = path.join(dir, 'main-file-only.db');
    fs.copyFileSync(dbPath, copy);
    const conn = new Database(copy, { readonly: true });
    try {
      const rows = conn.prepare('SELECT label FROM host_labels').all();
      assert.deepEqual(rows.map((r) => r.label), [`before ${signal}`]);
    } finally {
      conn.close();
    }
  });
}
