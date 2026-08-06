'use strict';

// API tokens (v1.25.0) need a real SQLite — point DB_PATH at a throwaway
// file BEFORE requiring db (the module opens the database at import time;
// the test runner gives each test file its own process, so this can't leak).
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
const {
  generateToken,
  hashToken,
  parseBearerHeader,
  requireAuth,
} = require('../src/auth');
const { validateTokenName } = require('../src/http-validators');

// ----- validator ------------------------------------------------------------

test('validateTokenName trims, requires content and caps the length', () => {
  assert.deepEqual(validateTokenName('  backup-cron  '), { value: 'backup-cron' });
  assert.ok(validateTokenName(undefined).error);
  assert.ok(validateTokenName(42).error);
  assert.ok(validateTokenName('   ').error);
  assert.ok(validateTokenName('x'.repeat(65)).error);
  assert.deepEqual(validateTokenName('x'.repeat(64)), { value: 'x'.repeat(64) });
});

// ----- token material -------------------------------------------------------

test('generateToken mints unique lsk_-prefixed 64-hex tokens', () => {
  const a = generateToken();
  const b = generateToken();
  assert.match(a, /^lsk_[0-9a-f]{64}$/);
  assert.match(b, /^lsk_[0-9a-f]{64}$/);
  assert.notEqual(a, b);
});

test('hashToken is deterministic and never echoes the token', () => {
  const t = generateToken();
  assert.equal(hashToken(t), hashToken(t));
  assert.match(hashToken(t), /^[0-9a-f]{64}$/);
  assert.ok(!hashToken(t).includes(t.slice(4, 20)));
});

test('parseBearerHeader accepts only well-shaped lanscope tokens', () => {
  const t = generateToken();
  assert.equal(parseBearerHeader(`Bearer ${t}`), t);
  assert.equal(parseBearerHeader(`bearer ${t}`), t); // scheme is case-insensitive
  for (const bad of [
    undefined,
    42,
    '',
    'Bearer',
    'Bearer not-a-token',
    'Bearer lsk_short',
    `Basic ${Buffer.from('a:b').toString('base64')}`,
    `Bearer ${t.toUpperCase()}`, // hex body is lowercase by construction
  ]) {
    assert.equal(parseBearerHeader(bad), null, `should reject ${String(bad)}`);
  }
});

// ----- middleware -----------------------------------------------------------

function fakeExchange(authorization) {
  const res = {
    headers: {},
    statusCode: null,
    body: null,
    set(k, v) { this.headers[k] = v; return this; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
  return { req: { headers: authorization ? { authorization } : {} }, res };
}

function b64(s) {
  return Buffer.from(s, 'utf8').toString('base64');
}

test('requireAuth lets a known token through and records the use', () => {
  const t = generateToken();
  let touched = null;
  const mw = requireAuth({
    user: 'ops',
    pass: 'hunter2',
    findTokenByHash: (h) => (h === hashToken(t) ? { id: 7, name: 'ci' } : null),
    markTokenUsed: (id) => { touched = id; },
  });
  const { req, res } = fakeExchange(`Bearer ${t}`);
  let passed = false;
  mw(req, res, () => { passed = true; });
  assert.ok(passed, 'next() should have been called');
  assert.equal(touched, 7, 'last_used_at hook should fire');
  assert.equal(res.statusCode, null);
});

test('requireAuth rejects unknown or revoked tokens with the same 401 as Basic', () => {
  const mw = requireAuth({
    user: 'ops',
    pass: 'hunter2',
    findTokenByHash: () => null, // nothing in the table (or just revoked)
    markTokenUsed: () => { throw new Error('must not mark an unknown token'); },
  });
  const { req, res } = fakeExchange(`Bearer ${generateToken()}`);
  let passed = false;
  mw(req, res, () => { passed = true; });
  assert.ok(!passed);
  assert.equal(res.statusCode, 401);
  assert.match(res.headers['WWW-Authenticate'], /^Basic realm=/);
  assert.equal(res.body.error, 'Authentication required');
});

test('requireAuth still honours the Basic credential alongside tokens', () => {
  const mw = requireAuth({
    user: 'ops',
    pass: 'hunter2',
    findTokenByHash: () => null,
    markTokenUsed: () => {},
  });
  const good = fakeExchange(`Basic ${b64('ops:hunter2')}`);
  let passed = false;
  mw(good.req, good.res, () => { passed = true; });
  assert.ok(passed, 'valid Basic must still work');

  const bad = fakeExchange(`Basic ${b64('ops:wrong')}`);
  passed = false;
  mw(bad.req, bad.res, () => { passed = true; });
  assert.ok(!passed);
  assert.equal(bad.res.statusCode, 401);
});

// ----- persistence ----------------------------------------------------------

test('create/list/find/touch/delete round-trip, and the hash never leaves', () => {
  const t = generateToken();
  const created = db.createApiToken('backup-cron', hashToken(t));
  assert.ok(created.id > 0);

  const listed = db.listApiTokens();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].name, 'backup-cron');
  assert.ok(listed[0].created_at > 0);
  assert.equal(listed[0].last_used_at, null);
  assert.ok(!('token_hash' in listed[0]), 'the hash must never be listed');

  const found = db.findApiTokenByHash(hashToken(t));
  assert.equal(found.id, created.id);
  assert.equal(db.findApiTokenByHash(hashToken(generateToken())), null);

  db.touchApiToken(created.id);
  assert.ok(db.listApiTokens()[0].last_used_at > 0, 'touch must stamp last_used_at');

  assert.ok(db.deleteApiToken(created.id));
  assert.ok(!db.deleteApiToken(created.id), 'second delete finds nothing');
  assert.equal(db.findApiTokenByHash(hashToken(t)), null, 'a revoked token stops matching');
});

test('token names are unique — a duplicate insert throws', () => {
  db.createApiToken('grafana', hashToken(generateToken()));
  assert.throws(
    () => db.createApiToken('grafana', hashToken(generateToken())),
    /UNIQUE/,
  );
});
