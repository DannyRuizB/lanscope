'use strict';

// host-search.js is a pure, DOM-free module with a module.exports fallback,
// so it runs under node --test directly (no sandbox, no browser).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { matchHost, searchHosts } = require('../src/public/host-search');

const HOSTS = [
  {
    ip: '192.168.1.1', mac: '9C:9D:7E:11:22:33', vendor: 'TP-LINK', hostname: 'router.lan',
    os_matches: [{ name: 'Linux 5.x' }],
    ports: [{ port: 80, state: 'open' }, { port: 443, state: 'open' }],
  },
  {
    ip: '192.168.1.42', mac: 'AC:DE:48:00:11:22', vendor: 'Apple, Inc.', hostname: 'iphone.lan',
    os_matches: [{ name: 'iOS 17' }],
    ports: [{ port: 62078, state: 'open' }],
  },
  {
    ip: '192.168.1.50', mac: 'DC:A6:32:aa:bb:cc', vendor: 'Raspberry Pi', hostname: 'pihole.lan',
    os_matches: [],
    ports: [{ port: 22, state: 'open' }, { port: 53, state: 'closed' }],
  },
];

test('an empty or whitespace query matches everything (no filter)', () => {
  assert.equal(searchHosts(HOSTS, '').length, 3);
  assert.equal(searchHosts(HOSTS, '   ').length, 3);
  assert.equal(searchHosts(HOSTS, undefined).length, 3);
});

test('search matches IP fragments', () => {
  const r = searchHosts(HOSTS, '1.42');
  assert.equal(r.length, 1);
  assert.equal(r[0].ip, '192.168.1.42');
});

test('search is case-insensitive over vendor and hostname', () => {
  assert.equal(searchHosts(HOSTS, 'apple').length, 1);
  assert.equal(searchHosts(HOSTS, 'PIHOLE')[0].hostname, 'pihole.lan');
  assert.equal(searchHosts(HOSTS, 'raspberry')[0].ip, '192.168.1.50');
});

test('search matches MAC fragments and OS names', () => {
  assert.equal(searchHosts(HOSTS, '9c:9d')[0].ip, '192.168.1.1');
  assert.equal(searchHosts(HOSTS, 'ios')[0].ip, '192.168.1.42');
});

test('search matches OPEN port numbers only (closed ports are not indexed)', () => {
  // 62078 is open on the iphone and appears in no other field of any host
  const open = searchHosts(HOSTS, '62078');
  assert.equal(open.length, 1);
  assert.equal(open[0].ip, '192.168.1.42');
  // 53 is closed on the pi -> not matched by port (and no other field has 53)
  assert.equal(searchHosts(HOSTS, '53').length, 0);
  // NB: search is a plain substring over the whole haystack, so a short
  // query like "22" also hits MACs containing "…11:22…" — by design.
  assert.equal(searchHosts(HOSTS, '22').length, 3);
});

test('the friendly label is searchable via the labelFor lookup', () => {
  const labelFor = (ip) => (ip === '192.168.1.50' ? "Danny's Pi-hole" : null);
  const r = searchHosts(HOSTS, 'pi-hole', labelFor);
  assert.equal(r.length, 1);
  assert.equal(r[0].ip, '192.168.1.50');
  // Without the lookup, "pi-hole" (with the dash) matches nothing.
  assert.equal(searchHosts(HOSTS, 'pi-hole').length, 0);
});

test('a non-matching query returns an empty list', () => {
  assert.equal(searchHosts(HOSTS, 'zzz-nothing').length, 0);
});

test('matchHost is the single-host predicate behind searchHosts', () => {
  assert.equal(matchHost(HOSTS[0], 'tp-link'), true);
  assert.equal(matchHost(HOSTS[0], 'apple'), false);
  assert.equal(matchHost(HOSTS[0], ''), true);
});
