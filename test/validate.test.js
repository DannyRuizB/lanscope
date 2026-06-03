'use strict';

// Pure input validators from src/scanner.js. These guard everything that
// reaches the nmap argv, so they get exhaustive happy-path + rejection tests.
// No nmap, no network — the functions are pure string/shape checks.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const S = require('../src/scanner');

test('validateCidr accepts valid CIDRs and rejects bad input', () => {
  assert.equal(S.validateCidr('192.168.1.0/24'), null);
  assert.equal(S.validateCidr('10.0.0.0/8'), null);
  assert.match(S.validateCidr('10.0.0.0/33'), /invalid CIDR/);
  assert.match(S.validateCidr('256.1.1.0/24'), /invalid CIDR/);
  assert.match(S.validateCidr('not-a-cidr'), /invalid CIDR/);
  assert.match(S.validateCidr(42), /must be a string/);
});

test('validateIpv4 accepts dotted quads and rejects out-of-range', () => {
  assert.equal(S.validateIpv4('192.168.1.5'), null);
  assert.match(S.validateIpv4('999.1.1.1'), /invalid IPv4/);
  assert.match(S.validateIpv4(null), /must be a string/);
});

test('validateTiming treats empty as default and validates T0..T5', () => {
  assert.deepEqual(S.validateTiming(undefined), { value: null, error: null });
  assert.deepEqual(S.validateTiming(''), { value: null, error: null });
  assert.deepEqual(S.validateTiming('T4'), { value: 'T4', error: null });
  assert.equal(S.validateTiming('T9').value, null);
  assert.match(S.validateTiming('T9').error, /T0\.\.T5/);
});

test('validateScanType accepts connect/syn only', () => {
  assert.deepEqual(S.validateScanType('syn'), { value: 'syn', error: null });
  assert.deepEqual(S.validateScanType('connect'), { value: 'connect', error: null });
  assert.deepEqual(S.validateScanType(''), { value: null, error: null });
  assert.match(S.validateScanType('xmas').error, /connect.*syn/);
});

test('validateScripts allowlists default/safe and rejects everything else', () => {
  assert.deepEqual(S.validateScripts(undefined), { args: [], error: null });
  assert.deepEqual(S.validateScripts([]), { args: [], error: null });
  assert.deepEqual(S.validateScripts(['default', 'safe']), {
    args: ['--script=default,safe'],
    error: null,
  });
  assert.match(S.validateScripts(['vuln']).error, /not allowed/);
  assert.match(S.validateScripts('default').error, /must be an array/);
});

test('validateDiscovery maps skipPing / pingTypes to nmap flags', () => {
  assert.deepEqual(S.validateDiscovery({ skipPing: true }), { args: ['-Pn'], error: null });
  assert.deepEqual(S.validateDiscovery({ pingTypes: ['PE', 'PS'] }), {
    args: ['-PE', '-PS'],
    error: null,
  });
  assert.deepEqual(S.validateDiscovery(undefined), { args: [], error: null });
  assert.match(S.validateDiscovery({ pingTypes: ['ZZ'] }).error, /not allowed/);
  assert.match(S.validateDiscovery(['nope']).error, /must be an object/);
});

test('validatePortsSpec handles default, top-N and range, rejecting bad specs', () => {
  assert.deepEqual(S.validatePortsSpec(), { args: ['--top-ports', '100'], error: null });
  assert.deepEqual(S.validatePortsSpec({ mode: 'top', value: 1000 }), {
    args: ['--top-ports', '1000'],
    error: null,
  });
  assert.deepEqual(S.validatePortsSpec({ mode: 'range', value: '22,80,443' }), {
    args: ['-p', '22,80,443'],
    error: null,
  });
  assert.match(S.validatePortsSpec({ mode: 'top', value: 70000 }).error, /1\.\.65535/);
  assert.match(S.validatePortsSpec({ mode: 'range', value: '80-1' }).error, /invalid port token/);
  assert.match(S.validatePortsSpec({ mode: 'bogus' }).error, /top.*range/);
});
