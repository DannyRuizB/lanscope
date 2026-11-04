'use strict';

// v1.57.0 — src/backup.js. The live database is the server's own: point
// DB_PATH at a throwaway file BEFORE requiring db (it opens the database at
// import time, in WAL mode, exactly as the server does), write through it,
// and never close it — the backup has to work while LanScope runs.
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-test-'));
process.env.DB_PATH = path.join(dataDir, 'lanscope.db');

const { test } = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const db = require('../src/db');
const { snapshot, check } = require('../src/backup');

const CIDR = '192.168.50.0/24';
for (const n of [1, 2, 3]) db.upsertLabel({ cidr: CIDR, ip: `192.168.50.${n}`, label: `probe-${n}` });

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-backup-test-'));
const BACKUP = path.join(__dirname, '..', 'src', 'backup.js');

function labelsIn(file) {
  const conn = new Database(file, { readonly: true, fileMustExist: true });
  try {
    const table = conn.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'host_labels'").get();
    return table ? conn.prepare('SELECT label FROM host_labels ORDER BY ip').all().map((r) => r.label) : null;
  } finally {
    conn.close();
  }
}

test('the recipe the FAQ shipped up to 1.56.0 — copy lanscope.db alone — loses what is still in the WAL', () => {
  // Not a test of our code: of the hazard the README now warns about. While
  // the server runs, the schema and the rows sit in lanscope.db-wal.
  assert.ok(fs.statSync(`${process.env.DB_PATH}-wal`).size > 0);
  const copy = path.join(scratch, 'main-file-only.db');
  fs.copyFileSync(process.env.DB_PATH, copy);
  assert.equal(labelsIn(copy), null, 'the bare main file has no host_labels table at all');
});

test('snapshot: a consistent standalone copy of the live database, WAL included', () => {
  const dest = path.join(scratch, 'snap.db');
  const r = snapshot(process.env.DB_PATH, dest);
  assert.equal(r.ok, true);
  assert.equal(r.result, 'ok');
  assert.equal(r.counts.host_labels, 3);
  assert.equal(r.counts.scans, 0);
  assert.deepEqual(labelsIn(dest), ['probe-1', 'probe-2', 'probe-3']);
  // Standalone: a rollback-journal file with no log beside it.
  assert.equal(fs.existsSync(`${dest}-wal`), false);
  const conn = new Database(dest, { readonly: true });
  assert.equal(conn.pragma('journal_mode', { simple: true }), 'delete');
  conn.close();
});

test('snapshot leaves the data directory exactly as it found it', () => {
  const before = fs.readdirSync(dataDir).sort();
  snapshot(process.env.DB_PATH, path.join(scratch, 'again.db'));
  assert.deepEqual(fs.readdirSync(dataDir).sort(), before);
});

test('snapshot never overwrites an existing file', () => {
  // An earlier backup: SQLite refuses to VACUUM INTO a database with content.
  const earlier = path.join(scratch, 'earlier.db');
  snapshot(process.env.DB_PATH, earlier);
  const bytes = fs.readFileSync(earlier);
  assert.throws(() => snapshot(process.env.DB_PATH, earlier), /output file already exists/);
  assert.deepEqual(fs.readFileSync(earlier), bytes);
  // Anything else: it is not a database, so SQLite will not write into it.
  const other = path.join(scratch, 'notes.txt');
  fs.writeFileSync(other, 'not a database, and not ours to clobber');
  assert.throws(() => snapshot(process.env.DB_PATH, other), /file is not a database/);
  assert.equal(fs.readFileSync(other, 'utf8'), 'not a database, and not ours to clobber');
});

test('check: integrity ok and the row counts', () => {
  const r = check(process.env.DB_PATH);
  assert.equal(r.ok, true);
  assert.equal(r.counts.host_labels, 3);
});

test('CLI: streams a backup to stdout that opens with every row', () => {
  const out = spawnSync(process.execPath, [BACKUP], { env: { ...process.env }, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(out.status, 0, out.stderr.toString());
  const file = path.join(scratch, 'from-stdout.db');
  fs.writeFileSync(file, out.stdout);
  assert.deepEqual(labelsIn(file), ['probe-1', 'probe-2', 'probe-3']);
  assert.match(out.stderr.toString(), /integrity ok; 0 scans, 0 hosts, 3 host_labels/);
});

test('CLI: --check prints the verdict, and a missing database is a named failure', () => {
  const ok = spawnSync(process.execPath, [BACKUP, '--check'], { env: { ...process.env }, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /integrity ok; 0 scans, 0 hosts, 3 host_labels/);

  const missing = path.join(scratch, 'nope', 'lanscope.db');
  const bad = spawnSync(process.execPath, [BACKUP], { env: { ...process.env, DB_PATH: missing }, encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout, '');
  assert.match(bad.stderr, /^lanscope backup: /);
  assert.equal(fs.existsSync(missing), false, 'a backup must not create the database it was asked to copy');

  const usage = spawnSync(process.execPath, [BACKUP, '--frobnicate'], { env: { ...process.env }, encoding: 'utf8' });
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /^usage: /);
});
