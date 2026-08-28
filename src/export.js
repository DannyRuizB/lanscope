// Scan export (v1.1.0). CSV is one row per host with port data aggregated
// into flat columns so the file opens cleanly in Excel / LibreOffice; the
// JSON variant is just the scan object as already served by the API, so the
// endpoint only needs the CSV builder and the filename helper from here.

const CSV_COLUMNS = [
  "ip",
  "label",
  "mac",
  "vendor",
  "hostname",
  "status",
  "latency_ms",
  "os",
  "os_accuracy",
  "tcp_open_ports",
  "tcp_services",
  "udp_open_ports",
];

// RFC 4180: quote a field when it carries a comma, a quote or a line break,
// doubling any embedded quotes. nmap service banners ("Apache httpd 2.4,
// mod_ssl") are the usual offenders.
function csvField(value) {
  if (value === null || value === undefined) return "";
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function hostToRow(host, labelsByIp = {}) {
  const bestOs = (host.os_matches || [])[0] || null;
  const openTcp = (host.ports || []).filter((p) => p.state === "open");
  // Same criterion as the UI's "responsive" pill: plain open only —
  // "open|filtered" means nmap couldn't tell, which is not an inventory fact.
  const openUdp = (host.udp_ports || []).filter((p) => p.state === "open");

  const services = openTcp
    .map((p) => {
      const product = [p.product, p.version].filter(Boolean).join(" ");
      return `${p.port}/${p.service || "unknown"}${product ? ` (${product})` : ""}`;
    })
    .join("; ");

  return [
    host.ip,
    labelsByIp[host.ip] || "",
    host.mac,
    host.vendor,
    host.hostname,
    host.status,
    host.latency_ms ?? "",
    bestOs ? bestOs.name : "",
    bestOs ? bestOs.accuracy : "",
    openTcp.map((p) => p.port).join(" "),
    services,
    openUdp.map((p) => p.port).join(" "),
  ];
}

// UTF-8 BOM up front so Excel detects the encoding instead of mangling
// vendor names like "Zyxel Communications Ç"; CRLF line endings per RFC 4180.
function scanToCsv(scan, labelsByIp = {}) {
  const lines = [CSV_COLUMNS.join(",")];
  for (const host of scan.hosts || []) {
    lines.push(hostToRow(host, labelsByIp).map(csvField).join(","));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

// lanscope_scan-12_192-168-1-0_24.csv — everything outside [A-Za-z0-9_-]
// becomes "-" so the CIDR's dots and slash can't break Content-Disposition.
function exportFilename(scan, format) {
  const cidr = String(scan.cidr || "scan").replace(/[^A-Za-z0-9_-]+/g, "-");
  return `lanscope_scan-${scan.id}_${cidr}.${format}`;
}

// v1.10.0 — host-history export. One row per scan of the host's network, in
// the same chronological order as the modal chart. Absent scans keep their
// row (present=false) so the file shows the gaps, not a compacted history.
const HISTORY_COLUMNS = [
  "scan_id",
  "started_at",
  "present",
  "status",
  "latency_ms",
  "hostname",
  "tcp_open_ports",
];

function historyToCsv(history) {
  const lines = [HISTORY_COLUMNS.join(",")];
  for (const p of history.points || []) {
    lines.push([
      p.scan_id,
      p.started_at ? new Date(p.started_at).toISOString() : "",
      p.present ? "true" : "false",
      p.status ?? "",
      p.latency_ms ?? "",
      p.hostname ?? "",
      p.tcp_open_ports ?? "",
    ].map(csvField).join(","));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

// lanscope_host-history_192-168-1-42_192-168-1-0_24.csv
function historyFilename(history, format) {
  const ip = String(history.ip || "host").replace(/[^A-Za-z0-9_-]+/g, "-");
  const cidr = String(history.cidr || "net").replace(/[^A-Za-z0-9_-]+/g, "-");
  return `lanscope_host-history_${ip}_${cidr}.${format}`;
}

// v1.19.0 — alert export. The payload is a different shape per alert type
// (a latency finding carries latency_ms, an exposure one a port list), so the
// CSV cannot have a column per field without a column per type. Two columns
// carry it instead: `detail`, the same human sentence the UI's alert row
// shows — that's the one you paste into a ticket — and `payload_json`, the
// raw object for whoever wants to parse it. JSON export needs neither: it
// hands back the alerts exactly as the API does.
const ALERT_COLUMNS = [
  "id",
  "created_at",
  "acknowledged_at",
  "status",
  "type",
  "cidr",
  "scan_id",
  "ip",
  "hostname",
  "detail",
  "payload_json",
];

// The same sentences the sidebar renders (fmtAlertDetail in src/public/app.js),
// so an exported report and the screen agree word for word. Deliberately
// duplicated rather than shared: app.js is a DOM script, not a module this can
// require. The payload field names differ per type and are NOT guessable —
// `before`/`after` for the changed_* family, `added`/`removed` for ports,
// `last_seen_hostname` for a host that vanished — so a test pins one line per
// alert type against real payloads; a silent divergence would otherwise ship
// an export full of "?" that looks fine in review.
function alertDetail(alert) {
  const p = alert.payload || {};
  const ip = p.ip || "?";
  switch (alert.type) {
    case "appeared": {
      const parts = [ip];
      if (p.hostname) parts.push(p.hostname);
      if (p.mac) parts.push(p.mac);
      return `New host: ${parts.join(" · ")}`;
    }
    case "disappeared": {
      const parts = [ip];
      if (p.last_seen_hostname) parts.push(p.last_seen_hostname);
      return `Host gone: ${parts.join(" · ")}`;
    }
    case "changed_mac":
      return `${ip}: MAC ${p.before || "?"} → ${p.after || "?"}`;
    case "changed_hostname":
      return `${ip}: hostname ${p.before || "?"} → ${p.after || "?"}`;
    case "changed_os":
      return `${ip}: OS ${p.before || "?"} → ${p.after || "?"}`;
    case "changed_ports": {
      const added = (p.added || []).join(", ") || "—";
      const removed = (p.removed || []).join(", ") || "—";
      return `${ip}: ports added [${added}], removed [${removed}]`;
    }
    case "high_latency": {
      const who = p.hostname ? `${ip} (${p.hostname})` : ip;
      return `${who}: latency ${p.latency_ms} ms ≥ threshold ${p.threshold_ms} ms`;
    }
    case "sensitive_port": {
      const who = p.hostname ? `${ip} (${p.hostname})` : ip;
      const list = (p.ports || [])
        .map((x) => (x.service ? `${x.port}/${x.service}` : String(x.port)))
        .join(", ");
      return `${who}: watched port${(p.ports || []).length === 1 ? "" : "s"} open — ${list}`;
    }
    default:
      return ip;
  }
}

function alertsToCsv(alerts) {
  const lines = [ALERT_COLUMNS.join(",")];
  for (const a of alerts || []) {
    const p = a.payload || {};
    lines.push([
      a.id,
      a.created_at ? new Date(a.created_at).toISOString() : "",
      a.acknowledged_at ? new Date(a.acknowledged_at).toISOString() : "",
      a.acknowledged_at ? "acknowledged" : "pending",
      a.type,
      a.cidr ?? "",
      a.scan_id ?? "",
      p.ip ?? "",
      p.hostname ?? "",
      alertDetail(a),
      JSON.stringify(a.payload ?? {}),
    ].map(csvField).join(","));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

// Scan diff export (v1.33.0): one row per host the compare view classified,
// state first. A diff report is the WHOLE picture — appeared, disappeared,
// changed AND unchanged (the no-limit principle of the alert export) — and
// the changed rows carry the reasons plus the base-side values, so the file
// shows WHAT changed, not just that something did. Disappeared rows are the
// base scan's hosts: the base side is the only place they still exist.
const DIFF_CSV_COLUMNS = [
  "state",
  "ip",
  "label",
  "mac",
  "vendor",
  "hostname",
  "reasons",
  "base_mac",
  "base_hostname",
];

function diffRow(state, host, labelsByIp, reasons, base) {
  return [
    state,
    host.ip,
    labelsByIp[host.ip] || "",
    host.mac,
    host.vendor,
    host.hostname,
    (reasons || []).join(" "),
    base ? base.mac : "",
    base ? base.hostname : "",
  ];
}

function diffToCsv(diff, labelsByIp = {}) {
  const lines = [DIFF_CSV_COLUMNS.join(",")];
  for (const h of diff.appeared) lines.push(diffRow("appeared", h, labelsByIp).map(csvField).join(","));
  for (const h of diff.disappeared) lines.push(diffRow("disappeared", h, labelsByIp).map(csvField).join(","));
  for (const c of diff.changed) lines.push(diffRow("changed", c.host, labelsByIp, c.reasons, c.base).map(csvField).join(","));
  for (const h of diff.unchanged) lines.push(diffRow("unchanged", h, labelsByIp).map(csvField).join(","));
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

// lanscope_diff_12-vs-15_192-168-1-0_24.csv — base first, like the banner.
function diffFilename(baseScan, newScan, format) {
  const cidr = String(newScan.cidr).replace(/[^A-Za-z0-9_-]+/g, "-");
  return `lanscope_diff_${baseScan.id}-vs-${newScan.id}_${cidr}.${format}`;
}

// lanscope_alerts_192-168-1-0_24.csv, or lanscope_alerts_all.csv with no
// CIDR filter — the filename says what the file actually contains.
function alertsFilename(filters, format) {
  const scope = filters && filters.cidr
    ? String(filters.cidr).replace(/[^A-Za-z0-9_-]+/g, "-")
    : "all";
  return `lanscope_alerts_${scope}.${format}`;
}

module.exports = {
  scanToCsv, exportFilename, csvField, historyToCsv, historyFilename,
  alertsToCsv, alertsFilename, alertDetail, diffToCsv, diffFilename,
};
