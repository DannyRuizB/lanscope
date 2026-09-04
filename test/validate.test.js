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

test('validateVersionDetection maps the three levels and defaults absent to light', () => {
  // Absent/null/empty must reproduce the historical --version-light so every
  // pre-v1.32 scan is byte-identical.
  assert.deepEqual(S.validateVersionDetection(undefined), { args: ['--version-light'], error: null });
  assert.deepEqual(S.validateVersionDetection(null), { args: ['--version-light'], error: null });
  assert.deepEqual(S.validateVersionDetection(''), { args: ['--version-light'], error: null });
  assert.deepEqual(S.validateVersionDetection('light'), { args: ['--version-light'], error: null });
  assert.deepEqual(S.validateVersionDetection('standard'), { args: [], error: null });
  assert.deepEqual(S.validateVersionDetection('all'), { args: ['--version-all'], error: null });
  for (const bad of ['intense', 'LIGHT', '9', 9, {}, ['all']]) {
    assert.equal(S.validateVersionDetection(bad).args, null, `should reject ${JSON.stringify(bad)}`);
    assert.match(S.validateVersionDetection(bad).error, /light.*standard.*all/);
  }
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

test('validateScripts de-duplicates categories', () => {
  assert.deepEqual(S.validateScripts(['default', 'safe', 'default']), {
    args: ['--script=default,safe'],
    error: null,
  });
});

test('validateDiscovery de-dupes ping types, and skipPing wins over them', () => {
  assert.deepEqual(S.validateDiscovery({ pingTypes: ['PE', 'PE', 'PS'] }), {
    args: ['-PE', '-PS'],
    error: null,
  });
  assert.deepEqual(S.validateDiscovery({ skipPing: false, pingTypes: ['PA'] }), {
    args: ['-PA'],
    error: null,
  });
  assert.deepEqual(S.validateDiscovery({ skipPing: true, pingTypes: ['PE'] }), {
    args: ['-Pn'],
    error: null,
  });
});

test('validateCidr accepts the /0 and /32 boundaries', () => {
  assert.equal(S.validateCidr('0.0.0.0/0'), null);
  assert.equal(S.validateCidr('192.168.1.1/32'), null);
});

test('validatePortsSpec accepts single-port / multi-token ranges and a stringified top-N', () => {
  assert.deepEqual(S.validatePortsSpec({ mode: 'range', value: '443' }), {
    args: ['-p', '443'],
    error: null,
  });
  assert.deepEqual(S.validatePortsSpec({ mode: 'range', value: '22,80,8000-8100' }), {
    args: ['-p', '22,80,8000-8100'],
    error: null,
  });
  assert.deepEqual(S.validatePortsSpec({ mode: 'top', value: '50' }), {
    args: ['--top-ports', '50'],
    error: null,
  });
});

// v1.36.0 — sweep exclusions. The joined list reaches nmap's argv, so the
// allowlist is strict and every rejection names the offending entry.
test('validateExclude: absent means no --exclude; blanks and duplicates collapse', () => {
  assert.deepEqual(S.validateExclude(undefined), { args: [], error: null });
  assert.deepEqual(S.validateExclude(null), { args: [], error: null });
  assert.deepEqual(S.validateExclude([]), { args: [], error: null });
  assert.deepEqual(S.validateExclude(['', '  ']), { args: [], error: null });
  assert.deepEqual(S.validateExclude([' 10.0.0.1 ', '10.0.0.1', '10.0.0.0/30']), { args: ['--exclude', '10.0.0.1,10.0.0.0/30'], error: null });
});

test('validateExclude: dotted quads, CIDRs and last-octet ranges are allowed', () => {
  assert.deepEqual(S.validateExclude(['192.168.1.1']).args, ['--exclude', '192.168.1.1']);
  assert.deepEqual(S.validateExclude(['192.168.1.64/26']).args, ['--exclude', '192.168.1.64/26']);
  assert.deepEqual(S.validateExclude(['192.168.1.20-29']).args, ['--exclude', '192.168.1.20-29']);
  assert.deepEqual(S.validateExclude(['10.0.0.5-5']).args, ['--exclude', '10.0.0.5-5'], 'a one-host range is a valid range');
  assert.deepEqual(S.validateExclude(['10.0.0.0-255']).args, ['--exclude', '10.0.0.0-255']);
});

test('validateExclude: hostnames, IPv6, wildcards, bad octets and inverted ranges are refused by name', () => {
  for (const bad of ['printer.local', 'fe80::1', '192.168.1.*', '192.168.1.300', '192.168.1.0/33', '192.168.1.20-300', '192.168.1.29-20', '192.168.1-20.5', '10.0.0.1;rm -rf /', '--top-ports']) {
    const r = S.validateExclude([bad]);
    assert.equal(r.args, null, `expected rejection for ${bad}`);
    assert.match(r.error, new RegExp(`not allowed: ${bad.replace(/[.*+?^${}()|[\]\\;/-]/g, '\\$&')}`));
  }
});

test('validateExclude: shape errors — not an array, non-string entries, too many', () => {
  assert.match(S.validateExclude('10.0.0.1').error, /must be an array/);
  assert.match(S.validateExclude({ host: '10.0.0.1' }).error, /must be an array/);
  assert.match(S.validateExclude([10]).error, /must be strings/);
  assert.match(S.validateExclude(Array.from({ length: 65 }, (_, i) => `10.0.0.${i}`)).error, /at most 64/);
  assert.equal(S.validateExclude(Array.from({ length: 64 }, (_, i) => `10.0.0.${i}`)).error, null);
});

// v1.37.0 — packet-rate cap. An enum: exactly four spellings reach nmap.
test('validateRate: absent or unlimited means no flag; the three presets map to --max-rate', () => {
  assert.deepEqual(S.validateRate(undefined), { args: [], error: null });
  assert.deepEqual(S.validateRate(null), { args: [], error: null });
  assert.deepEqual(S.validateRate(''), { args: [], error: null });
  assert.deepEqual(S.validateRate('unlimited'), { args: [], error: null });
  assert.deepEqual(S.validateRate('500'), { args: ['--max-rate', '500'], error: null });
  assert.deepEqual(S.validateRate('100'), { args: ['--max-rate', '100'], error: null });
  assert.deepEqual(S.validateRate('25'), { args: ['--max-rate', '25'], error: null });
});

test('validateRate: free integers, other strings, numbers and prototype keys are refused', () => {
  for (const bad of ['50', '1000', '0', 'fast', 'MAX', 'toString', 'constructor', '--max-rate 10']) {
    const r = S.validateRate(bad);
    assert.equal(r.args, null, `expected rejection for ${bad}`);
    assert.match(r.error, /rate must be/);
  }
  assert.match(S.validateRate(100).error, /rate must be/, 'a number, not the string');
  assert.match(S.validateRate(['100']).error, /rate must be/);
});

test('validateHostTimeout: absent or none means no flag; the three presets map to --host-timeout; anything else is refused', () => {
  assert.deepEqual(S.validateHostTimeout(undefined), { args: [], error: null });
  assert.deepEqual(S.validateHostTimeout(''), { args: [], error: null });
  assert.deepEqual(S.validateHostTimeout('none'), { args: [], error: null });
  assert.deepEqual(S.validateHostTimeout('30s'), { args: ['--host-timeout', '30s'], error: null });
  assert.deepEqual(S.validateHostTimeout('2m'), { args: ['--host-timeout', '2m'], error: null });
  assert.deepEqual(S.validateHostTimeout('5m'), { args: ['--host-timeout', '5m'], error: null });
  for (const bad of ['10s', '1h', 30, '30s; rm -rf /', ['30s']]) {
    assert.match(S.validateHostTimeout(bad).error, /host_timeout must be/);
  }
});
