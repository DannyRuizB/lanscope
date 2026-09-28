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

// --- v1.44.0: UDP ports, and the partial-scan filter -------------------------

test('a UDP port that ANSWERED is searchable, as the module always promised (fix)', () => {
  const snmp = { ip: '10.0.0.9', ports: [{ port: 22, state: 'open' }], udp_ports: [{ port: 161, state: 'open' }] };
  assert.equal(matchHost(snmp, '161'), true);
  assert.equal(matchHost(snmp, '22'), true);
});

test('an open|filtered UDP port is NOT searchable: nmap got no reply and cannot tell', () => {
  const quiet = { ip: '10.0.0.10', ports: [], udp_ports: [{ port: 53, state: 'open|filtered' }] };
  assert.equal(matchHost(quiet, '53'), false);
});

test('is:timedout lists the hosts whose TCP or UDP port scan hit the per-host timeout', () => {
  const hosts = [
    { ip: '10.0.0.1', port_timedout: 1, udp_port_timedout: 0 },
    { ip: '10.0.0.2', port_timedout: 0, udp_port_timedout: 1 },
    { ip: '10.0.0.3', port_timedout: 0, udp_port_timedout: 0 },
    { ip: '10.0.0.4' },
  ];
  assert.deepEqual(searchHosts(hosts, 'is:timedout').map((h) => h.ip), ['10.0.0.1', '10.0.0.2']);
  assert.deepEqual(searchHosts(hosts, '  IS:TimedOut ').map((h) => h.ip), ['10.0.0.1', '10.0.0.2']);
});

test('is:timedout is a keyword, not a substring: a host named "timedout" is not a partial scan', () => {
  const hosts = [{ ip: '10.0.0.5', hostname: 'is-timedout-box', port_timedout: 0 }];
  assert.equal(searchHosts(hosts, 'is:timedout').length, 0);
  assert.equal(searchHosts(hosts, 'timedout').length, 1);
});

// v1.45.0 — terms, keywords and negation.
const FLEET = [
  { ip: '10.0.0.1', mac: 'AA:BB:CC:22:33:44', status: 'up', hostname: 'nas',
    ports: [{ port: 2222, state: 'open' }], udp_ports: [] },
  { ip: '10.0.0.22', mac: 'AA:BB:CC:00:00:01', status: 'up', hostname: 'pi',
    ports: [{ port: 22, state: 'open' }, { port: 80, state: 'open' }], udp_ports: [{ port: 161, state: 'open' }] },
  { ip: '10.0.0.3', mac: 'AA:BB:CC:00:00:02', status: 'down', hostname: 'printer',
    ports: [{ port: 22, state: 'closed' }], udp_ports: [{ port: 22, state: 'open|filtered' }] },
  { ip: '10.0.0.4', mac: 'AA:BB:CC:00:00:03', status: 'up', hostname: 'switch',
    ports: [], udp_ports: [{ port: 161, state: 'open' }] },
];
const ips = (q, labelFor) => searchHosts(FLEET, q, labelFor).map((h) => h.ip);

test('port:N is exact: the substring 22 also hits a MAC, an IP and port 2222; port:22 only the open 22', () => {
  assert.deepEqual(ips('22'), ['10.0.0.1', '10.0.0.22']);
  assert.deepEqual(ips('port:22'), ['10.0.0.22']);
  assert.deepEqual(ips('port:2222'), ['10.0.0.1']);
});

test('port: covers TCP and UDP; tcp: and udp: pick one; closed and open|filtered never count', () => {
  assert.deepEqual(ips('port:161'), ['10.0.0.22', '10.0.0.4']);
  assert.deepEqual(ips('tcp:161'), []);
  assert.deepEqual(ips('udp:161'), ['10.0.0.22', '10.0.0.4']);
  assert.deepEqual(ips('tcp:22'), ['10.0.0.22']);
  assert.deepEqual(ips('udp:22'), []);
});

test('is:up / is:down / is:labeled', () => {
  assert.deepEqual(ips('is:up'), ['10.0.0.1', '10.0.0.22', '10.0.0.4']);
  assert.deepEqual(ips('is:down'), ['10.0.0.3']);
  const labels = { '10.0.0.4': 'Core switch', '10.0.0.1': '   ' };
  assert.deepEqual(ips('is:labeled', (ip) => labels[ip] || null), ['10.0.0.4']);
});

test('terms are ANDed, a leading - negates, and keywords are case-insensitive', () => {
  assert.deepEqual(ips('is:up udp:161'), ['10.0.0.22', '10.0.0.4']);
  assert.deepEqual(ips('IS:UP  UDP:161   -Port:22'), ['10.0.0.4']);
  assert.deepEqual(ips('-is:up'), ['10.0.0.3']);
  assert.deepEqual(ips('pi port:80'), ['10.0.0.22']);
});

test('a keyword with a value it cannot use matches nothing (no silent fallback to the substring)', () => {
  for (const q of ['port:ssh', 'port:0', 'port:65536', 'tcp:', 'is:nope', 'is:']) {
    assert.deepEqual(ips(q), [], q);
  }
  assert.deepEqual(ips('-'), [], 'a lone dash is a substring term');
});

test('multi-word text still works as before: every word must appear', () => {
  const hosts = [{ ip: '192.168.1.42', vendor: 'Apple, Inc.', hostname: 'iphone.lan' }];
  assert.equal(searchHosts(hosts, 'Apple, Inc.').length, 1);
  assert.equal(searchHosts(hosts, 'apple iphone').length, 1);
  assert.equal(searchHosts(hosts, 'apple android').length, 0);
});
