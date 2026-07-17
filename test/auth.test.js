'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { basicAuth, parseBasicHeader, safeEqual } = require('../src/auth');

function b64(s) {
  return Buffer.from(s, 'utf8').toString('base64');
}

test('parseBasicHeader decodes a well-formed header', () => {
  const creds = parseBasicHeader(`Basic ${b64('admin:s3cret')}`);
  assert.deepEqual(creds, { user: 'admin', pass: 's3cret' });
});

test('parseBasicHeader keeps colons inside the password (only the first separates)', () => {
  const creds = parseBasicHeader(`Basic ${b64('admin:pa:ss:word')}`);
  assert.deepEqual(creds, { user: 'admin', pass: 'pa:ss:word' });
});

test('parseBasicHeader rejects malformed input', () => {
  for (const bad of [
    undefined,
    42,
    '',
    'Bearer token',
    'Basic',
    'Basic !!!not-base64!!!',
    `Basic ${b64('no-colon-here')}`,
  ]) {
    assert.equal(parseBasicHeader(bad), null, `should reject ${String(bad)}`);
  }
});

test('safeEqual matches equal strings and rejects different ones without length leaks', () => {
  assert.ok(safeEqual('secret', 'secret'));
  assert.ok(!safeEqual('secret', 'Secret'));
  // Different lengths must be comparable (sha256 fixes the buffer length).
  assert.ok(!safeEqual('short', 'a-much-longer-password'));
});

// Minimal fake req/res pair — enough surface for the middleware.
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

test('basicAuth lets a valid credential through', () => {
  const mw = basicAuth({ user: 'ops', pass: 'hunter2' });
  const { req, res } = fakeExchange(`Basic ${b64('ops:hunter2')}`);
  let passed = false;
  mw(req, res, () => { passed = true; });
  assert.ok(passed, 'next() should have been called');
  assert.equal(res.statusCode, null, 'no response should have been written');
});

test('basicAuth rejects wrong password, wrong user, and missing header with 401 + challenge', () => {
  const mw = basicAuth({ user: 'ops', pass: 'hunter2' });
  for (const header of [
    `Basic ${b64('ops:wrong')}`,
    `Basic ${b64('intruder:hunter2')}`,
    undefined,
  ]) {
    const { req, res } = fakeExchange(header);
    let passed = false;
    mw(req, res, () => { passed = true; });
    assert.ok(!passed, `next() must not run for ${String(header)}`);
    assert.equal(res.statusCode, 401);
    assert.match(res.headers['WWW-Authenticate'], /^Basic realm=/);
    assert.equal(res.body.error, 'Authentication required');
  }
});
