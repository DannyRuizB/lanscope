const { test } = require("node:test");
const assert = require("node:assert/strict");
const { scanToCsv, exportFilename, csvField } = require("../src/export");

// --- csvField: RFC 4180 escaping ---------------------------------------------

test("csvField passes plain values through untouched", () => {
  assert.equal(csvField("192.168.1.1"), "192.168.1.1");
  assert.equal(csvField(443), "443");
});

test("csvField turns null/undefined into the empty string", () => {
  assert.equal(csvField(null), "");
  assert.equal(csvField(undefined), "");
});

test("csvField quotes fields with commas", () => {
  assert.equal(csvField("Apache httpd 2.4, mod_ssl"), '"Apache httpd 2.4, mod_ssl"');
});

test("csvField doubles embedded quotes", () => {
  assert.equal(csvField('say "hi"'), '"say ""hi"""');
});

test("csvField quotes fields with line breaks", () => {
  assert.equal(csvField("two\nlines"), '"two\nlines"');
});

// --- scanToCsv ----------------------------------------------------------------

function fixtureScan() {
  return {
    id: 7,
    cidr: "192.168.1.0/24",
    hosts: [
      {
        ip: "192.168.1.1",
        mac: "AA:BB:CC:DD:EE:FF",
        vendor: "Zyxel, Communications",
        hostname: "router.lan",
        status: "up",
        os_matches: [{ name: "Linux 5.X", accuracy: 96 }],
        ports: [
          { port: 22, state: "open", service: "ssh", product: "OpenSSH", version: "9.2" },
          { port: 80, state: "open", service: "http", product: null, version: null },
          { port: 443, state: "closed", service: "https", product: null, version: null },
        ],
        udp_ports: [
          { port: 53, state: "open", service: "domain" },
          { port: 161, state: "open|filtered", service: "snmp" },
        ],
      },
      {
        ip: "192.168.1.50",
        mac: null,
        vendor: null,
        hostname: null,
        status: "up",
        os_matches: [],
        ports: [],
        udp_ports: [],
      },
    ],
  };
}

test("scanToCsv starts with the UTF-8 BOM and the header row", () => {
  const csv = scanToCsv(fixtureScan());
  assert.ok(csv.startsWith("﻿"));
  assert.ok(
    csv
      .slice(1)
      .startsWith("ip,mac,vendor,hostname,status,os,os_accuracy,tcp_open_ports,tcp_services,udp_open_ports"),
  );
});

test("scanToCsv uses CRLF line endings and ends with one", () => {
  const csv = scanToCsv(fixtureScan());
  assert.ok(csv.endsWith("\r\n"));
  assert.equal(csv.split("\r\n").length, 4); // header + 2 hosts + trailing empty
});

test("scanToCsv aggregates only open TCP ports and open UDP ports", () => {
  const rows = scanToCsv(fixtureScan()).split("\r\n");
  const router = rows[1];
  assert.ok(router.includes("22 80")); // 443 is closed → out
  assert.ok(router.includes("22/ssh (OpenSSH 9.2); 80/http"));
  assert.ok(!router.includes("443"));
  assert.ok(router.endsWith(",53")); // udp 161 is open|filtered → out
});

test("scanToCsv quotes the vendor that carries a comma", () => {
  const rows = scanToCsv(fixtureScan()).split("\r\n");
  assert.ok(rows[1].includes('"Zyxel, Communications"'));
});

test("scanToCsv leaves unknown fields empty on bare hosts", () => {
  const rows = scanToCsv(fixtureScan()).split("\r\n");
  assert.equal(rows[2], "192.168.1.50,,,,up,,,,,");
});

test("scanToCsv handles a scan with no hosts", () => {
  const csv = scanToCsv({ id: 1, cidr: "10.0.0.0/24", hosts: [] });
  assert.equal(csv.split("\r\n").length, 2); // header + trailing empty
});

// --- exportFilename -----------------------------------------------------------

test("exportFilename sanitizes the CIDR for Content-Disposition", () => {
  const name = exportFilename({ id: 7, cidr: "192.168.1.0/24" }, "csv");
  assert.equal(name, "lanscope_scan-7_192-168-1-0-24.csv");
});

test("exportFilename works for json and survives a missing cidr", () => {
  assert.equal(exportFilename({ id: 3, cidr: null }, "json"), "lanscope_scan-3_scan.json");
});
