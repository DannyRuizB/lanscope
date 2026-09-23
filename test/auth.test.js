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

// ===== Session cookies (v1.34.0) =====
const {
  makeSessionCookie, verifySessionCookie, readCookie, requireAuth,
} = require('../src/auth');

test('a fresh session cookie verifies back to its user', () => {
  const c = makeSessionCookie({ user: 'admin', ttlMs: 3600e3, pass: 'p@ss' });
  assert.equal(verifySessionCookie({ value: c, pass: 'p@ss' }), 'admin');
});

test('a tampered payload or a wrong key fails to verify (one shape: null)', () => {
  const c = makeSessionCookie({ user: 'admin', ttlMs: 3600e3, pass: 'p@ss' });
  const [payload, mac] = c.split('.');
  // Flip the payload, keep the MAC: signature no longer matches.
  const forged = `${payload}x.${mac}`;
  assert.equal(verifySessionCookie({ value: forged, pass: 'p@ss' }), null);
  // Right cookie, wrong signing key (a rotated password).
  assert.equal(verifySessionCookie({ value: c, pass: 'different' }), null);
  // Garbage.
  assert.equal(verifySessionCookie({ value: 'not-a-cookie', pass: 'p@ss' }), null);
  assert.equal(verifySessionCookie({ value: '', pass: 'p@ss' }), null);
});

test('an expired session cookie is rejected (exp is baked in and signed)', () => {
  const now = 1_000_000_000_000;
  const c = makeSessionCookie({ user: 'admin', ttlMs: 1000, pass: 'p@ss', now });
  assert.equal(verifySessionCookie({ value: c, pass: 'p@ss', now: now + 500 }), 'admin');
  assert.equal(verifySessionCookie({ value: c, pass: 'p@ss', now: now + 1500 }), null);
});

test('SESSION_SECRET overrides the password-derived key (survives a rotation)', () => {
  const c = makeSessionCookie({ user: 'admin', ttlMs: 3600e3, pass: 'p1', secret: 'fixed-secret' });
  // Password changed, but the fixed secret still validates.
  assert.equal(verifySessionCookie({ value: c, pass: 'p2', secret: 'fixed-secret' }), 'admin');
  // ...and without the secret (password-derived) it does not.
  assert.equal(verifySessionCookie({ value: c, pass: 'p2' }), null);
});

test('readCookie picks the named cookie out of a header, ignores the rest', () => {
  const h = 'theme=dark; lanscope_session=abc.def; other=1';
  assert.equal(readCookie(h, 'lanscope_session'), 'abc.def');
  assert.equal(readCookie(h, 'missing'), null);
  assert.equal(readCookie(undefined, 'lanscope_session'), null);
});

test('requireAuth accepts a valid session cookie and rejects a forged one', () => {
  const mw = requireAuth({
    user: 'admin', pass: 'p@ss',
    findTokenByHash: () => null, markTokenUsed: () => {},
  });
  const good = makeSessionCookie({ user: 'admin', ttlMs: 3600e3, pass: 'p@ss' });
  let nexted = false;
  mw({ headers: { cookie: `lanscope_session=${good}` } }, { set() {}, status() { return { json() {} }; } }, () => { nexted = true; });
  assert.ok(nexted, 'valid cookie should call next()');

  let status = 0;
  const res = { set() {}, status(c) { status = c; return { json() {} }; } };
  mw({ headers: { cookie: 'lanscope_session=forged.nope' }, method: 'GET' }, res, () => { status = 200; });
  assert.equal(status, 401, 'a forged cookie with no other credential gets the 401');
});

// ===== Basic shares the login throttle (v1.43.0) =====
// Basic carries AUTH_PASS — the same password as the login form — so it
// must spend the same per-address budget, or the form's throttle is a
// door with a window next to it.
const { createLoginThrottle } = require('../src/login-throttle');
const { generateToken, hashToken } = require('../src/auth');

function basicAt(mw, header, addr) {
  const { req, res } = fakeExchange(header);
  req.socket = { remoteAddress: addr };
  let passed = false;
  mw(req, res, () => { passed = true; });
  return { passed, res };
}

test('wrong Basic guesses close the door with a named 429 + Retry-After, before the credential is evaluated', () => {
  const throttle = createLoginThrottle({ maxAttempts: 3, windowMs: 60_000 });
  const mw = basicAuth({ user: 'ops', pass: 'hunter2', throttle });
  for (let i = 0; i < 3; i++) {
    assert.equal(basicAt(mw, `Basic ${b64(`ops:guess${i}`)}`, '10.0.0.9').res.statusCode, 401);
  }
  const wrong = basicAt(mw, `Basic ${b64('ops:guess3')}`, '10.0.0.9');
  assert.equal(wrong.res.statusCode, 429);
  assert.match(wrong.res.body.error, /too many failed logins/);
  assert.ok(Number(wrong.res.headers['Retry-After']) >= 1);
  // The RIGHT password is refused too while limited — that is the point:
  // otherwise the attacker's next guess is still being checked.
  const right = basicAt(mw, `Basic ${b64('ops:hunter2')}`, '10.0.0.9');
  assert.ok(!right.passed);
  assert.equal(right.res.statusCode, 429);
});

test('Basic and the login form spend ONE budget per address', () => {
  const throttle = createLoginThrottle({ maxAttempts: 3, windowMs: 60_000 });
  const mw = basicAuth({ user: 'ops', pass: 'hunter2', throttle });
  throttle.recordFailure('10.0.0.9'); // two failures on the form...
  throttle.recordFailure('10.0.0.9');
  assert.equal(basicAt(mw, `Basic ${b64('ops:x')}`, '10.0.0.9').res.statusCode, 401); // ...one on Basic
  assert.equal(throttle.check('10.0.0.9').limited, true, 'the form is now limited by a Basic guess');
});

test('a request with no Basic header is a challenge, not a guess — never counted', () => {
  const throttle = createLoginThrottle({ maxAttempts: 1, windowMs: 60_000 });
  const mw = basicAuth({ user: 'ops', pass: 'hunter2', throttle });
  for (let i = 0; i < 5; i++) assert.equal(basicAt(mw, undefined, '10.0.0.9').res.statusCode, 401);
  assert.equal(throttle.check('10.0.0.9').limited, false);
  assert.ok(basicAt(mw, `Basic ${b64('ops:hunter2')}`, '10.0.0.9').passed);
});

test('addresses stay isolated and a good Basic login clears its slate', () => {
  const throttle = createLoginThrottle({ maxAttempts: 2, windowMs: 60_000 });
  const mw = basicAuth({ user: 'ops', pass: 'hunter2', throttle });
  basicAt(mw, `Basic ${b64('ops:a')}`, '10.0.0.66');
  basicAt(mw, `Basic ${b64('ops:b')}`, '10.0.0.66');
  assert.equal(basicAt(mw, `Basic ${b64('ops:hunter2')}`, '10.0.0.66').res.statusCode, 429);
  assert.ok(basicAt(mw, `Basic ${b64('ops:hunter2')}`, '10.0.0.7').passed, 'another address is unaffected');
  basicAt(mw, `Basic ${b64('ops:c')}`, '10.0.0.8');
  assert.ok(basicAt(mw, `Basic ${b64('ops:hunter2')}`, '10.0.0.8').passed);
  assert.equal(throttle.check('10.0.0.8').limited, false);
  basicAt(mw, `Basic ${b64('ops:d')}`, '10.0.0.8');
  assert.equal(throttle.check('10.0.0.8').limited, false, 'the success reset the count: one failure, not two');
});

test('a limited address keeps a valid session cookie and a valid token — neither consults the counter', () => {
  const throttle = createLoginThrottle({ maxAttempts: 1, windowMs: 60_000 });
  throttle.recordFailure('10.0.0.9');
  const token = generateToken();
  const mw = requireAuth({
    user: 'admin', pass: 'p@ss', throttle,
    findTokenByHash: (h) => (h === hashToken(token) ? { id: 1, scope: 'full', bound_cidr: null } : null),
    markTokenUsed: () => {},
  });
  const cookie = makeSessionCookie({ user: 'admin', ttlMs: 3600e3, pass: 'p@ss' });
  for (const headers of [{ cookie: `lanscope_session=${cookie}` }, { authorization: `Bearer ${token}` }]) {
    let nexted = false;
    mw({ headers, method: 'POST', socket: { remoteAddress: '10.0.0.9' } }, { set() {}, status() { return { json() {} }; } }, () => { nexted = true; });
    assert.ok(nexted, `${Object.keys(headers)[0]} should still open the door while the address is limited`);
  }
  assert.equal(throttle.check('10.0.0.9').limited, true);
});
