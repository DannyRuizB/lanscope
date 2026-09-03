"use strict";

// v1.38.0 — remembered exclusions per network: the per-CIDR store and the
// merge that joins it with a request's own list. DB_PATH at a throwaway
// file BEFORE requiring db (the module opens the database on load).
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
process.env.DB_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), 'lanscope-excl-')),
  'test.db',
);

const { test } = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const S = require('../src/scanner');

test('network exclusions: absent is an empty list; set replaces; empty clears', () => {
  assert.deepEqual(db.getNetworkExclusions('10.9.0.0/24'), []);
  assert.deepEqual(db.setNetworkExclusions('10.9.0.0/24', ['10.9.0.1', '10.9.0.20-29']), ['10.9.0.1', '10.9.0.20-29']);
  assert.deepEqual(db.getNetworkExclusions('10.9.0.0/24'), ['10.9.0.1', '10.9.0.20-29']);
  assert.deepEqual(db.setNetworkExclusions('10.9.0.0/24', ['10.9.0.64/26']), ['10.9.0.64/26'], 'PUT is a replace, not an append');
  assert.deepEqual(db.getNetworkExclusions('10.9.0.0/24'), ['10.9.0.64/26']);
  assert.deepEqual(db.getNetworkExclusions('10.8.0.0/24'), [], 'per network');
  assert.deepEqual(db.setNetworkExclusions('10.9.0.0/24', []), []);
  assert.deepEqual(db.getNetworkExclusions('10.9.0.0/24'), [], 'an empty list forgets the network');
});

test('mergeExcludes: union in order, first occurrence wins, blanks and non-arrays ignored', () => {
  assert.deepEqual(S.mergeExcludes(['10.0.0.1', '10.0.0.0/30'], ['10.0.0.1', ' 10.0.0.9 ', '']), ['10.0.0.1', '10.0.0.0/30', '10.0.0.9']);
  assert.deepEqual(S.mergeExcludes([], undefined, null, 'not-a-list'), []);
  assert.deepEqual(S.mergeExcludes(undefined, ['10.0.0.2']), ['10.0.0.2']);
});

test('the merged list goes through the same allowlist: a bad remembered entry is still a 400-class error', () => {
  const merged = S.mergeExcludes(db.setNetworkExclusions('10.7.0.0/24', ['10.7.0.1']), ['printer.local']);
  const v = S.validateExclude(merged);
  assert.equal(v.args, null);
  assert.match(v.error, /not allowed: printer.local/);
  assert.deepEqual(S.validateExclude(S.mergeExcludes(db.getNetworkExclusions('10.7.0.0/24'), [])).args, ['--exclude', '10.7.0.1'], 'an empty request still carries the remembered list');
});
