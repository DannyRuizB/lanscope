'use strict';

// Pure nmap-XML parsers from src/scanner.js. We feed hand-written nmap XML
// (the same shape `nmap -oX -` produces) and assert the normalized model —
// no nmap binary, no network, no host touched.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const S = require('../src/scanner');

const HOSTS_XML = `<?xml version="1.0"?><nmaprun>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Raspberry Pi"/>
    <hostnames><hostname name="pi.local" type="PTR"/></hostnames>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="11:22:33:44:55:66" addrtype="mac"/>
  </host>
</nmaprun>`;

const PORTS_XML = `<nmaprun><host>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.4p1" extrainfo="protocol 2.0"/>
      <script id="ssh-hostkey" output="2048 abc&#xa;256 def"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="closed" reason="conn-refused"/>
      <service name="http"/>
    </port>
  </ports>
</host></nmaprun>`;

test('parseHosts normalizes hosts and drops entries without an IPv4', () => {
  assert.deepEqual(S.parseHosts(HOSTS_XML), [
    {
      ip: '192.168.1.10',
      mac: 'AA:BB:CC:DD:EE:FF',
      vendor: 'Raspberry Pi',
      hostname: 'pi.local',
      status: 'up',
      reason: 'arp-response',
    },
    {
      ip: '192.168.1.11',
      mac: null,
      vendor: null,
      hostname: null,
      status: 'down',
      reason: 'no-response',
    },
  ]);
});

test('parseHosts returns [] for an empty run', () => {
  assert.deepEqual(S.parseHosts('<nmaprun></nmaprun>'), []);
});

test('parsePorts normalizes ports, service detail and script output', () => {
  assert.deepEqual(S.parsePorts(PORTS_XML), [
    {
      port: 22,
      protocol: 'tcp',
      state: 'open',
      state_reason: 'syn-ack',
      service: 'ssh',
      product: 'OpenSSH',
      version: '8.4p1',
      extra: 'protocol 2.0',
      scripts: [{ script_id: 'ssh-hostkey', output: '2048 abc\n256 def' }],
    },
    {
      port: 80,
      protocol: 'tcp',
      state: 'closed',
      state_reason: 'conn-refused',
      service: 'http',
      product: null,
      version: null,
      extra: null,
      scripts: [],
    },
  ]);
});

test('parsePorts decodes nmap numeric XML entities into real newlines', () => {
  const [ssh] = S.parsePorts(PORTS_XML);
  assert.ok(ssh.scripts[0].output.includes('\n'));
  assert.ok(!ssh.scripts[0].output.includes('&#x'));
});

test('parseHostScripts pulls host-level NSE script output', () => {
  const xml = `<nmaprun><host><hostscript>
    <script id="smb-os-discovery" output="OS: Windows&#xa;Name: PC"/>
  </hostscript></host></nmaprun>`;
  assert.deepEqual(S.parseHostScripts(xml), [
    { script_id: 'smb-os-discovery', output: 'OS: Windows\nName: PC' },
  ]);
});

test('parseOsMatches flattens osmatch + osclass into one record', () => {
  const xml = `<nmaprun><host><os>
    <osmatch name="Linux 5.4" accuracy="96" line="60">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"/>
    </osmatch>
  </os></host></nmaprun>`;
  assert.deepEqual(S.parseOsMatches(xml), [
    {
      name: 'Linux 5.4',
      accuracy: 96,
      line: 60,
      vendor: 'Linux',
      family: 'Linux',
      gen: '5.X',
      type: 'general purpose',
    },
  ]);
});
