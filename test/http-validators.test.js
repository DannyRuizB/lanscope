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

// --- host labels (v1.3.0) ------------------------------------------------

test('validateLabelText trims, caps at 64 and treats empty as null', () => {
  assert.equal(V.validateLabelText('  Office printer  ').value, 'Office printer');
  assert.equal(V.validateLabelText(null).value, null);
  assert.equal(V.validateLabelText(undefined).value, null);
  assert.equal(V.validateLabelText('   ').value, null); // whitespace-only clears
  assert.equal(V.validateLabelText('x'.repeat(64)).value, 'x'.repeat(64));
  assert.ok(V.validateLabelText('x'.repeat(65)).error);
  assert.ok(V.validateLabelText(42).error);
  assert.ok(V.validateLabelText(['a']).error);
});

test('validateNotesText trims, caps at 500 and treats empty as null', () => {
  assert.equal(V.validateNotesText(' rack 3, PSU B ').value, 'rack 3, PSU B');
  assert.equal(V.validateNotesText('').value, null);
  assert.equal(V.validateNotesText('x'.repeat(500)).value, 'x'.repeat(500));
  assert.ok(V.validateNotesText('x'.repeat(501)).error);
  assert.ok(V.validateNotesText({}).error);
});

// --- schedule retention (v1.8.0) ------------------------------------------

test('validateKeepLast accepts positive integers up to 10000, null clears', () => {
  assert.equal(V.validateKeepLast(1).value, 1);
  assert.equal(V.validateKeepLast(24).value, 24);
  assert.equal(V.validateKeepLast(10000).value, 10000);
  assert.equal(V.validateKeepLast(null).value, null);
  assert.equal(V.validateKeepLast(undefined).value, null);
  for (const bad of [0, -1, 1.5, 10001, '24', 'abc', true, {}, []]) {
    assert.ok(V.validateKeepLast(bad).error, `should reject ${JSON.stringify(bad)}`);
  }
});
