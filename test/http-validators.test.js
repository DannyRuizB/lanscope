'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const V = require('../src/http-validators');

test('validateHttpUrl accepts http(s) and rejects other schemes', () => {
  assert.equal(V.validateHttpUrl('https://ntfy.sh'), 'https://ntfy.sh');
  assert.equal(V.validateHttpUrl('http://10.0.0.5:8080/hook'), 'http://10.0.0.5:8080/hook');
  // Dangerous / non-http schemes must be rejected (null).
  for (const bad of ['file:///etc/passwd', 'javascript:alert(1)', 'ftp://x', 'gopher://x', 'not a url', '', 42]) {
    assert.equal(V.validateHttpUrl(bad), null, `should reject ${bad}`);
  }
});

test('validateScheduleName trims, requires non-empty, caps length', () => {
  assert.equal(V.validateScheduleName('  nightly  ').value, 'nightly');
  assert.ok(V.validateScheduleName('').error);
  assert.ok(V.validateScheduleName('   ').error);
  assert.ok(V.validateScheduleName('x'.repeat(81)).error);
  assert.ok(V.validateScheduleName(123).error);
});

test('validateCronExpr accepts valid cron and rejects garbage', () => {
  assert.equal(V.validateCronExpr('0 3 * * *').value, '0 3 * * *');
  assert.ok(V.validateCronExpr('not a cron').error);
  assert.ok(V.validateCronExpr('').error);
  assert.ok(V.validateCronExpr(null).error);
});

test('validateChannelType allowlists webhook / ntfy only', () => {
  assert.equal(V.validateChannelType('webhook').value, 'webhook');
  assert.equal(V.validateChannelType('ntfy').value, 'ntfy');
  assert.ok(V.validateChannelType('email').error);
  assert.ok(V.validateChannelType(undefined).error);
});

test('validateChannelConfig (webhook): needs a valid URL, defaults format to generic', () => {
  assert.deepEqual(
    V.validateChannelConfig('webhook', { url: 'https://hooks.example/x' }).value,
    { url: 'https://hooks.example/x', format: 'generic' },
  );
  assert.equal(
    V.validateChannelConfig('webhook', { url: 'https://x', format: 'discord' }).value.format,
    'discord',
  );
  assert.ok(V.validateChannelConfig('webhook', { url: 'file:///etc/passwd' }).error);
  assert.ok(V.validateChannelConfig('webhook', { url: 'https://x', format: 'sms' }).error);
  assert.ok(V.validateChannelConfig('webhook', null).error);
});

test('validateChannelConfig (ntfy): strict topic, defaults server to ntfy.sh', () => {
  const ok = V.validateChannelConfig('ntfy', { topic: 'home-lan_1' });
  assert.deepEqual(ok.value, { topic: 'home-lan_1', server: 'https://ntfy.sh' });
  // A self-hosted ntfy over http on the LAN is legitimate.
  assert.equal(
    V.validateChannelConfig('ntfy', { topic: 'x', server: 'http://10.0.0.9' }).value.server,
    'http://10.0.0.9',
  );
  // Topic charset is enforced (no slashes / spaces / injection).
  for (const bad of ['has space', 'a/b', 'x'.repeat(65), '', 'a;b']) {
    assert.ok(V.validateChannelConfig('ntfy', { topic: bad }).error, `reject topic ${bad}`);
  }
});

test('validateChannelEvents allowlists and de-dupes preserving order', () => {
  assert.deepEqual(
    V.validateChannelEvents(['scan_done', 'scan_error', 'scan_done']).value,
    ['scan_done', 'scan_error'],
  );
  assert.ok(V.validateChannelEvents([]).error);
  assert.ok(V.validateChannelEvents('scan_done').error);
  assert.ok(V.validateChannelEvents(['scan_done', 'nope']).error);
});
