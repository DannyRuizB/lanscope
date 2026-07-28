const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  scanToCsv, exportFilename, csvField, alertsToCsv, alertsFilename, alertDetail,
} = require("../src/export");

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
      .startsWith("ip,label,mac,vendor,hostname,status,latency_ms,os,os_accuracy,tcp_open_ports,tcp_services,udp_open_ports"),
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
  assert.equal(rows[2], "192.168.1.50,,,,,up,,,,,,");
});

test("scanToCsv carries latency_ms when the host has one (v1.4.0)", () => {
  const scan = fixtureScan();
  scan.hosts[0].latency_ms = 0.4;
  const rows = scanToCsv(scan).split("\r\n");
  assert.ok(rows[1].includes(",up,0.4,"));
});

test("scanToCsv fills the label column from the labels map (v1.3.0)", () => {
  const rows = scanToCsv(fixtureScan(), { "192.168.1.1": "Router — FTTH" }).split("\r\n");
  assert.ok(rows[1].startsWith("192.168.1.1,Router — FTTH,"));
  // Hosts without a label keep the column empty.
  assert.ok(rows[2].startsWith("192.168.1.50,,"));
});

test("scanToCsv quotes a label carrying a comma", () => {
  const rows = scanToCsv(fixtureScan(), { "192.168.1.1": "Router, main" }).split("\r\n");
  assert.ok(rows[1].includes('"Router, main"'));
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

// --- alert export (v1.19.0) ---------------------------------------------------

// One realistic payload per alert type: these field names are NOT guessable
// (before/after, added/removed, last_seen_hostname), and getting one wrong
// would ship an export full of "?" that still looks fine in review.
const ALERT_FIXTURES = [
  {
    alert: { type: "appeared", payload: { ip: "192.168.1.9", hostname: "nas.lan", mac: "AA:BB:CC:DD:EE:09" } },
    detail: "New host: 192.168.1.9 · nas.lan · AA:BB:CC:DD:EE:09",
  },
  {
    alert: { type: "disappeared", payload: { ip: "192.168.1.7", last_seen_hostname: "printer.lan" } },
    detail: "Host gone: 192.168.1.7 · printer.lan",
  },
  {
    alert: { type: "changed_mac", payload: { ip: "192.168.1.5", before: "AA:BB:CC:00:00:01", after: "AA:BB:CC:00:00:02" } },
    detail: "192.168.1.5: MAC AA:BB:CC:00:00:01 → AA:BB:CC:00:00:02",
  },
  {
    alert: { type: "changed_hostname", payload: { ip: "192.168.1.5", before: "old.lan", after: "new.lan" } },
    detail: "192.168.1.5: hostname old.lan → new.lan",
  },
  {
    alert: { type: "changed_os", payload: { ip: "192.168.1.5", before: "Linux", after: "Windows" } },
    detail: "192.168.1.5: OS Linux → Windows",
  },
  {
    alert: { type: "changed_ports", payload: { ip: "192.168.1.5", added: [8080], removed: [22, 80] } },
    detail: "192.168.1.5: ports added [8080], removed [22, 80]",
  },
  {
    alert: { type: "high_latency", payload: { ip: "192.168.1.30", hostname: "phone.lan", latency_ms: 250, threshold_ms: 50 } },
    detail: "192.168.1.30 (phone.lan): latency 250 ms ≥ threshold 50 ms",
  },
  {
    alert: {
      type: "sensitive_port",
      payload: {
        ip: "192.168.1.10",
        hostname: "desktop-win.lan",
        ports: [{ port: 445, service: "microsoft-ds" }, { port: 3389, service: "ms-wbt-server" }],
      },
    },
    detail: "192.168.1.10 (desktop-win.lan): watched ports open — 445/microsoft-ds, 3389/ms-wbt-server",
  },
];

test("alertDetail renders the same sentence the UI shows, for every alert type", () => {
  for (const { alert, detail } of ALERT_FIXTURES) {
    assert.equal(alertDetail(alert), detail, `detail for ${alert.type}`);
  }
});

test("alertDetail degrades to the IP on an unknown type and a missing payload", () => {
  assert.equal(alertDetail({ type: "brand_new", payload: { ip: "10.0.0.1" } }), "10.0.0.1");
  assert.equal(alertDetail({ type: "appeared" }), "New host: ?");
});

test("alertDetail says 'watched port' in the singular for one port", () => {
  const one = { type: "sensitive_port", payload: { ip: "10.0.0.2", ports: [{ port: 23, service: "telnet" }] } };
  assert.match(alertDetail(one), /watched port open — 23\/telnet$/);
});

function fixtureAlerts() {
  return [
    {
      id: 4,
      scan_id: 12,
      cidr: "192.168.1.0/24",
      type: "sensitive_port",
      payload: { ip: "192.168.1.10", hostname: "desktop-win.lan", ports: [{ port: 3389, service: "ms-wbt-server" }] },
      created_at: 1785200000000,
      acknowledged_at: null,
    },
    {
      id: 5,
      scan_id: 12,
      cidr: "192.168.1.0/24",
      type: "high_latency",
      payload: { ip: "192.168.1.30", hostname: null, latency_ms: 250, threshold_ms: 50 },
      created_at: 1785200001000,
      acknowledged_at: 1785200500000,
    },
  ];
}

test("alertsToCsv starts with the UTF-8 BOM, the header row and CRLF endings", () => {
  const csv = alertsToCsv(fixtureAlerts());
  assert.ok(csv.startsWith("﻿"), "BOM so Excel reads UTF-8");
  const rows = csv.split("\r\n");
  assert.equal(rows[0].replace("﻿", ""),
    "id,created_at,acknowledged_at,status,type,cidr,scan_id,ip,hostname,detail,payload_json");
  assert.equal(rows.length, 4); // header + 2 alerts + trailing empty
  assert.ok(csv.endsWith("\r\n"));
});

test("alertsToCsv carries the status, ISO timestamps and the human detail", () => {
  const rows = alertsToCsv(fixtureAlerts()).split("\r\n");
  assert.match(rows[1], /^4,2026-07-28T/);
  assert.ok(rows[1].includes(",pending,"), "an unacked alert is pending");
  assert.ok(rows[1].includes("watched port open — 3389/ms-wbt-server"));
  assert.ok(rows[2].includes(",acknowledged,"), "an acked alert carries its ack time and status");
  assert.match(rows[2], /,2026-07-28T[0-9:.]+Z,acknowledged,/);
});

test("alertsToCsv quotes the payload JSON so its commas don't split columns", () => {
  const rows = alertsToCsv(fixtureAlerts()).split("\r\n");
  // The raw payload travels in its own quoted field, with doubled quotes.
  assert.ok(rows[1].includes('"{""ip"":""192.168.1.10""'), "payload_json quoted + escaped");
  // Column count must survive the embedded commas: 11 fields, so 10 commas
  // outside quotes. Parsing back is the honest check.
  const fields = rows[1].match(/("([^"]|"")*"|[^,]*)(,|$)/g).filter((s) => s !== "");
  assert.equal(fields.length, 11);
});

test("alertsToCsv handles an empty alert list and a missing payload", () => {
  assert.equal(alertsToCsv([]).split("\r\n").length, 2); // header + trailing empty
  assert.equal(alertsToCsv(null).split("\r\n").length, 2);
  const bare = alertsToCsv([{ id: 1, type: "appeared", created_at: null, acknowledged_at: null }]);
  assert.ok(bare.includes("pending"));
  assert.ok(bare.includes("{}"), "a missing payload exports as an empty object");
});

// --- alertsFilename -----------------------------------------------------------

test("alertsFilename names the scope: the CIDR when filtered, 'all' when not", () => {
  assert.equal(alertsFilename({ cidr: "192.168.1.0/24" }, "csv"), "lanscope_alerts_192-168-1-0-24.csv");
  assert.equal(alertsFilename({}, "json"), "lanscope_alerts_all.json");
  assert.equal(alertsFilename(null, "csv"), "lanscope_alerts_all.csv");
});
