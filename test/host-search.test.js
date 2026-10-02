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

// --- v1.46.0: field keywords and quoted phrases ------------------------------
// Measured on the demo seed: `192.168.1.1` as a substring matches SEVEN hosts
// (.1 .10 .11 .12 .100 .101 .150); `ip:` is exact or a CIDR block.

const NET = ['1', '10', '11', '12', '100', '101', '150'].map((o) => ({
  ip: `192.168.1.${o}`, mac: '00:11:22:33:44:55', vendor: 'X', hostname: `h${o}.lan`, ports: [],
}));
const lastOctets = (q, hosts = NET) => searchHosts(hosts, q).map((h) => h.ip.split('.')[3]);

test('ip:A is exact - the substring 192.168.1.1 hits seven hosts, ip: one', () => {
  assert.equal(searchHosts(NET, '192.168.1.1').length, 7);
  assert.deepEqual(lastOctets('ip:192.168.1.1'), ['1']);
  assert.deepEqual(lastOctets('ip:192.168.1.10'), ['10']);
});

test('ip:A/N is a CIDR block, and negates like any term', () => {
  assert.deepEqual(lastOctets('ip:192.168.1.0/28'), ['1', '10', '11', '12']);
  assert.deepEqual(lastOctets('ip:192.168.1.96/27'), ['100', '101']);
  assert.deepEqual(lastOctets('ip:0.0.0.0/0'), ['1', '10', '11', '12', '100', '101', '150']);
  assert.deepEqual(lastOctets('-ip:192.168.1.0/25'), ['150']);
  // the host bits of the block itself do not matter, as in a route
  assert.deepEqual(lastOctets('ip:192.168.1.5/28'), ['1', '10', '11', '12']);
});

test('ip: with a value it cannot use matches NOTHING (no fallback to the substring)', () => {
  for (const q of ['ip:192.168.1.256', 'ip:192.168.1.0/33', 'ip:192.168', 'ip:router', 'ip:', 'ip:1.2.3.4/8/9', 'ip:192.168.1.0/x']) {
    assert.equal(searchHosts(NET, q).length, 0, q);
  }
});

test('mac: is a prefix (an OUI), with any separator or none', () => {
  const ips = (q) => searchHosts(HOSTS, q).map((h) => h.ip);
  assert.deepEqual(ips('mac:AC:DE:48'), ['192.168.1.42']);
  assert.deepEqual(ips('mac:ac-de-48'), ['192.168.1.42']);
  assert.deepEqual(ips('mac:acde48'), ['192.168.1.42']);
  // a prefix, not a substring: 11:22 sits inside two MACs but starts none
  assert.equal(searchHosts(HOSTS, '11:22').length, 2);
  assert.equal(searchHosts(HOSTS, 'mac:11:22').length, 0);
  assert.equal(searchHosts(HOSTS, 'mac:zz').length, 0);
});

test('vendor: / os: / name: look at their own field only', () => {
  const ips = (q, labelFor) => searchHosts(HOSTS, q, labelFor).map((h) => h.ip);
  // `pi` hits pihole's hostname AND its vendor; name: only the hostname
  assert.deepEqual(ips('pi'), ['192.168.1.50']);
  assert.deepEqual(ips('name:pihole'), ['192.168.1.50']);
  assert.deepEqual(ips('vendor:pihole'), []);
  assert.deepEqual(ips('vendor:raspberry'), ['192.168.1.50']);
  assert.deepEqual(ips('name:raspberry'), []);
  assert.deepEqual(ips('os:linux'), ['192.168.1.1']);
  assert.deepEqual(ips('os:router'), []);
  // name: covers the friendly label too
  assert.deepEqual(ips('name:garage', (ip) => (ip === '192.168.1.1' ? 'Garage AP' : null)), ['192.168.1.1']);
  // an empty value matches nothing
  assert.deepEqual(ips('vendor:'), []);
});

test('a double-quoted phrase keeps its spaces, alone, as a keyword value or negated', () => {
  const ips = (q) => searchHosts(HOSTS, q).map((h) => h.ip);
  assert.deepEqual(ips('"apple, inc."'), ['192.168.1.42']);
  assert.deepEqual(ips('vendor:"raspberry pi"'), ['192.168.1.50']);
  assert.deepEqual(ips('-"raspberry pi"'), ['192.168.1.1', '192.168.1.42']);
  // without quotes the same words are two terms that must both match somewhere
  assert.deepEqual(ips('raspberry router'), []);
  assert.deepEqual(ips('"raspberry router"'), []);
});

test('tokenize: quotes group, an unterminated quote runs to the end', () => {
  const { tokenize } = require('../src/public/host-search');
  assert.deepEqual([...tokenize('-vendor:"a b" port:22 "x y" -"z w" "open end')], ['-vendor:a b', 'port:22', 'x y', '-z w', 'open end']);
  assert.deepEqual([...tokenize('  ')], []);
});

// v1.47.0 — is:new / is:changed read the host's state in the ACTIVE
// comparison (scan-diff.js byIp states), passed as the 4th argument.
test('is:new / is:changed follow the active comparison, and AND with other terms', () => {
  const state = { '192.168.1.1': 'unchanged', '192.168.1.42': 'appeared', '192.168.1.50': 'changed' };
  const ips = (q) => searchHosts(HOSTS, q, null, (ip) => state[ip] || null).map((h) => h.ip);
  assert.deepEqual(ips('is:new'), ['192.168.1.42']);
  assert.deepEqual(ips('is:changed'), ['192.168.1.50']);
  assert.deepEqual(ips('-is:new'), ['192.168.1.1', '192.168.1.50']);
  assert.deepEqual(ips('is:changed port:22'), ['192.168.1.50']);
  assert.deepEqual(ips('is:changed port:443'), []);
});

test('is:new / is:changed match nothing with no comparison, and the UI is told why', () => {
  const { needsComparison } = require('../src/public/host-search');
  assert.equal(searchHosts(HOSTS, 'is:new').length, 0);
  assert.equal(searchHosts(HOSTS, 'is:changed', null, () => null).length, 0);
  // Anchor: the same query DOES match when a comparison is active.
  assert.equal(searchHosts(HOSTS, 'is:new', null, () => 'appeared').length, 3);
  assert.equal(needsComparison('port:22 is:new'), true);
  assert.equal(needsComparison('-IS:CHANGED'), true);
  assert.equal(needsComparison('is:up port:22'), false);
  assert.equal(needsComparison('"is:new"'), true, 'a quoted keyword is still the keyword');
  assert.equal(needsComparison(''), false);
});

test('a host literally named "new" is not is:new', () => {
  const hosts = [{ ip: '10.9.9.9', hostname: 'new', status: 'up' }];
  assert.equal(searchHosts(hosts, 'is:new', null, () => 'unchanged').length, 0);
  assert.equal(searchHosts(hosts, 'new').length, 1);
});

// v1.48.0 — is:gone (the disappeared rows, searched with state "disappeared").
test('is:gone matches only hosts whose state is disappeared, and needs a comparison', () => {
  const { needsComparison } = require('../src/public/host-search');
  const state = { '192.168.1.1': 'disappeared', '192.168.1.42': 'appeared', '192.168.1.50': 'unchanged' };
  const ips = (q) => searchHosts(HOSTS, q, null, (ip) => state[ip] || null).map((h) => h.ip);
  assert.deepEqual(ips('is:gone'), ['192.168.1.1']);
  assert.deepEqual(ips('is:gone port:443'), ['192.168.1.1']);
  assert.deepEqual(ips('is:gone port:22'), []);
  assert.equal(searchHosts(HOSTS, 'is:gone').length, 0, 'no comparison, nothing gone');
  assert.equal(needsComparison('is:gone'), true);
  assert.equal(needsComparison('-is:gone vendor:apple'), true);
});
