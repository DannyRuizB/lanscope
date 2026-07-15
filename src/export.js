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

module.exports = { scanToCsv, exportFilename, csvField };
