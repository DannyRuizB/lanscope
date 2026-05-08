const $ = (sel) => document.querySelector(sel);

const els = {
  form: $("#scan-form"),
  cidr: $("#cidr"),
  scanBtn: $("#scan-btn"),
  status: $("#scan-status"),
  refresh: $("#refresh-history"),
  clearHistory: $("#clear-history"),
  list: $("#scan-list"),
  resultsHeader: $("#results-header"),
  resultsCidr: $("#results-cidr"),
  resultsMeta: $("#results-meta"),
  empty: $("#results-empty"),
  table: $("#results-table"),
  body: $("#results-body"),
  deleteBtn: $("#delete-scan"),
  advTiming: $("#adv-timing"),
  advScanType: $("#adv-scantype"),
  advPortsTop: $("#adv-ports-top"),
  advPortsRange: $("#adv-ports-range"),
  advNseDefault: $("#adv-nse-default"),
  advNseSafe: $("#adv-nse-safe"),
  advDiscoSkip: $("#adv-disco-skip"),
  advDiscoPE: $("#adv-disco-pe"),
  advDiscoPS: $("#adv-disco-ps"),
  advDiscoPA: $("#adv-disco-pa"),
  advDiscoPR: $("#adv-disco-pr"),
  bulkPortscan: $("#bulk-portscan"),
  bulkOsscan: $("#bulk-osscan"),
  bulkUdpscan: $("#bulk-udpscan"),
};

function currentPortsSpec() {
  const mode = document.querySelector('input[name="adv-ports-mode"]:checked')?.value || "top";
  if (mode === "range") {
    return { mode: "range", value: els.advPortsRange?.value.trim() || "" };
  }
  const n = parseInt(els.advPortsTop?.value, 10);
  return { mode: "top", value: Number.isInteger(n) ? n : 100 };
}

function currentScriptsSpec() {
  const out = [];
  if (els.advNseDefault?.checked) out.push("default");
  if (els.advNseSafe?.checked) out.push("safe");
  return out;
}

function bindPortsModeToggle() {
  const radios = document.querySelectorAll('input[name="adv-ports-mode"]');
  const sync = () => {
    const mode = document.querySelector('input[name="adv-ports-mode"]:checked')?.value || "top";
    if (els.advPortsTop) els.advPortsTop.disabled = mode !== "top";
    if (els.advPortsRange) els.advPortsRange.disabled = mode !== "range";
  };
  radios.forEach((r) => r.addEventListener("change", sync));
  sync();
}
bindPortsModeToggle();

function currentDiscoverySpec() {
  if (els.advDiscoSkip?.checked) return { skipPing: true };
  const pingTypes = [];
  if (els.advDiscoPE?.checked) pingTypes.push("PE");
  if (els.advDiscoPS?.checked) pingTypes.push("PS");
  if (els.advDiscoPA?.checked) pingTypes.push("PA");
  if (els.advDiscoPR?.checked) pingTypes.push("PR");
  return pingTypes.length ? { pingTypes } : {};
}

function bindDiscoverySkipToggle() {
  const skip = els.advDiscoSkip;
  if (!skip) return;
  const others = [els.advDiscoPE, els.advDiscoPS, els.advDiscoPA, els.advDiscoPR];
  const sync = () => {
    const disabled = skip.checked;
    others.forEach((cb) => cb && (cb.disabled = disabled));
  };
  skip.addEventListener("change", sync);
  sync();
}
bindDiscoverySkipToggle();

let activeScanId = null;

function fmtTime(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleString();
}

function fmtDuration(scan) {
  if (!scan.finished_at || !scan.started_at) return "";
  const ms = scan.finished_at - scan.started_at;
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

function setStatus(text, isError = false) {
  if (!text) {
    els.status.hidden = true;
    return;
  }
  els.status.textContent = text;
  els.status.classList.toggle("error", isError);
  els.status.hidden = false;
}

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* ignore */
  }
  if (!res.ok) {
    const msg = body?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return body;
}

async function loadHistory() {
  try {
    const { scans } = await fetchJson("/api/scans");
    renderHistory(scans);
  } catch (e) {
    console.error("loadHistory failed:", e);
  }
}

function renderHistory(scans) {
  if (!scans.length) {
    els.list.innerHTML = `<li class="muted">No scans yet.</li>`;
    return;
  }
  els.list.innerHTML = scans
    .map(
      (s) => `
      <li data-id="${s.id}" class="${s.id === activeScanId ? "active" : ""}">
        <button class="scan-delete" data-id="${s.id}" title="Delete this scan" aria-label="Delete scan ${escapeHtml(s.cidr)}">×</button>
        <span class="scan-cidr">
          <span class="scan-status-dot ${s.status}"></span>${escapeHtml(s.cidr)}
        </span>
        <span class="scan-meta">
          ${fmtTime(s.started_at)} · ${s.host_count} host${s.host_count === 1 ? "" : "s"}
        </span>
      </li>`,
    )
    .join("");
  els.list.querySelectorAll("li[data-id]").forEach((li) => {
    li.addEventListener("click", () => loadScan(parseInt(li.dataset.id, 10)));
  });
  els.list.querySelectorAll(".scan-delete").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id, 10);
      const li = btn.closest("li");
      const cidr = li?.querySelector(".scan-cidr")?.textContent.trim() || "this scan";
      const ok = await confirmModal({
        title: "Delete scan",
        message: `${cidr} and all its host data will be permanently removed.`,
        confirmText: "Delete",
        danger: true,
      });
      if (!ok) return;
      try {
        await fetchJson(`/api/scans/${id}`, { method: "DELETE" });
        if (id === activeScanId) {
          activeScanId = null;
          lastScan = null;
          els.resultsHeader.hidden = true;
          els.deleteBtn.hidden = true;
          els.table.hidden = true;
          els.empty.hidden = false;
          els.empty.textContent = "Run a scan to see hosts here.";
        }
        await loadHistory();
      } catch (err) {
        setStatus(err.message, true);
      }
    });
  });
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

async function loadScan(id) {
  try {
    const scan = await fetchJson(`/api/scans/${id}`);
    activeScanId = id;
    renderScan(scan);
    document.querySelectorAll("#scan-list li").forEach((li) => {
      li.classList.toggle("active", parseInt(li.dataset.id, 10) === id);
    });
  } catch (e) {
    setStatus(e.message, true);
  }
}

function portsButtonLabel(host) {
  if (!host.portscanned_at) return "Scan ports";
  const open = (host.ports || []).filter((p) => p.state === "open").length;
  return `${open} open · ▾`;
}

function renderPortsButton(host) {
  if (host.status !== "up") return `<span class="muted">—</span>`;
  return `<button class="ghost small portscan-btn" data-host-id="${host.id}">${portsButtonLabel(host)}</button>`;
}

function udpStateClass(state) {
  if (state === "open") return "responsive";
  if (state === "open|filtered") return "unknown";
  return "closed-udp";
}

function udpStateLabel(state) {
  if (state === "open") return "responsive";
  if (state === "open|filtered") return "unknown";
  if (state === "closed") return "closed";
  return "filtered";
}

function udpButtonLabel(host) {
  if (!host.udp_portscanned_at) return "Scan UDP";
  const ports = host.udp_ports || [];
  const responsive = ports.filter((p) => p.state === "open").length;
  const unknown = ports.filter((p) => p.state === "open|filtered").length;
  if (responsive) return `${responsive} responsive · ▾`;
  if (unknown) return `${unknown} unknown · ▾`;
  return `0 responsive · ▾`;
}

function renderUdpButton(host) {
  if (host.status !== "up") return `<span class="muted">—</span>`;
  return `<button class="ghost small udpscan-btn" data-host-id="${host.id}">${udpButtonLabel(host)}</button>`;
}

function familyLetter(family) {
  if (!family) return "?";
  const f = family.toLowerCase();
  if (f.includes("linux")) return "L";
  if (f.includes("windows")) return "W";
  if (f.includes("mac") || f.includes("ios") || f.includes("apple")) return "M";
  if (f.includes("bsd")) return "B";
  if (f.includes("router") || f.includes("embedded") || f.includes("ros")) return "R";
  if (f.includes("solaris") || f.includes("aix") || f.includes("hp-ux")) return "U";
  return family[0].toUpperCase();
}

function topOsMatch(host) {
  return (host.os_matches || [])[0] || null;
}

function osChip(family) {
  const letter = familyLetter(family);
  const cls = letter === "?" ? "os-chip os-chip-unknown" : "os-chip";
  return `<span class="${cls}">${escapeHtml(letter)}</span>`;
}

function osButtonLabel(host) {
  if (!host.osscanned_at) return `<span class="osb-label">Scan OS</span>`;
  const top = topOsMatch(host);
  const family = top ? top.family : null;
  const label = top ? (top.family || top.name || "unknown") : "no match";
  return `${osChip(family)}<span class="osb-label">${escapeHtml(label)}</span><span class="osb-arrow">▾</span>`;
}

function renderOsButton(host) {
  if (host.status !== "up") return `<span class="muted">—</span>`;
  return `<button class="ghost small osscan-btn" data-host-id="${host.id}">${osButtonLabel(host)}</button>`;
}

function renderHostRow(h) {
  return `
    <tr class="host-row" data-host-id="${h.id}">
      <td class="ip">${escapeHtml(h.ip)}</td>
      <td class="${h.mac ? "" : "muted"}">${escapeHtml(h.mac) || "—"}</td>
      <td class="${h.vendor ? "" : "muted"}">${escapeHtml(h.vendor) || "—"}</td>
      <td class="${h.hostname ? "" : "muted"}">${escapeHtml(h.hostname) || "—"}</td>
      <td class="muted">${escapeHtml(h.reason) || "—"}</td>
      <td class="os-cell">${renderOsButton(h)}</td>
      <td class="ports-cell">${renderPortsButton(h)}</td>
      <td class="udp-cell">${renderUdpButton(h)}</td>
    </tr>
    <tr class="host-detail" data-host-id="${h.id}" data-kind="os" hidden>
      <td colspan="8">${h.os_matches?.length ? renderOsTable(h) : ""}</td>
    </tr>
    <tr class="host-detail" data-host-id="${h.id}" data-kind="ports" hidden>
      <td colspan="8">${h.ports?.length ? renderPortsTable(h) : ""}</td>
    </tr>
    <tr class="host-detail" data-host-id="${h.id}" data-kind="udp" hidden>
      <td colspan="8">${h.udp_ports?.length ? renderUdpPortsTable(h) : ""}</td>
    </tr>`;
}

function renderOsTable(host) {
  const matches = host.os_matches || [];
  if (!matches.length) {
    return `<div class="ports-empty">No OS match (host fingerprint inconclusive).</div>`;
  }
  const rows = matches
    .map(
      (m) => `
      <tr>
        <td class="os-name">${osChip(m.family)} ${escapeHtml(m.name)}</td>
        <td><span class="state-pill state-open">${m.accuracy}%</span></td>
        <td class="${m.family ? "" : "muted"}">${escapeHtml(m.family) || "—"}</td>
        <td class="${m.vendor ? "" : "muted"}">${escapeHtml(m.vendor) || "—"}</td>
        <td class="${m.type ? "" : "muted"}">${escapeHtml(m.type) || "—"}</td>
      </tr>`,
    )
    .join("");
  return `
    <table class="ports-table os-matches-table">
      <thead>
        <tr><th>Match</th><th>Accuracy</th><th>Family</th><th>Vendor</th><th>Type</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderPortStateCell(p) {
  const accessible = p.state === "open";
  const pillClass = accessible ? "state-open" : "state-unavailable";
  const label = accessible ? "accessible (TCP)" : "not available";
  const reason = p.state_reason || p.state;
  return `
    <span class="state-pill ${pillClass}">${label}</span>
    <div class="state-reason">${escapeHtml(reason)}</div>`;
}

const HTTP_SERVICES = new Set([
  "http",
  "http-alt",
  "http-proxy",
  "http-mgmt",
  "http-rpc-epmap",
]);
const HTTPS_SERVICES = new Set([
  "https",
  "https-alt",
  "ssl/http",
  "ssl/https",
]);

function portUrl(host, p) {
  if (!p.service || p.state !== "open") return null;
  const svc = p.service.toLowerCase();
  if (HTTP_SERVICES.has(svc)) return `http://${host.ip}:${p.port}`;
  if (HTTPS_SERVICES.has(svc)) return `https://${host.ip}:${p.port}`;
  return null;
}

const PORT_HINTS = {
  ssh: "SSH server — connect with an SSH client",
  ftp: "FTP — needs an FTP client (lftp, FileZilla)",
  "ftp-data": "FTP data channel — paired with port 21",
  telnet: "Telnet — needs telnet client (insecure)",
  smtp: "SMTP mail server — use a mail client",
  submission: "SMTP submission — use a mail client",
  domain: "DNS server — query with dig/nslookup",
  pop3: "POP3 mail — use a mail client",
  imap: "IMAP mail — use a mail client",
  msrpc: "Windows RPC — needs rpcclient/Impacket",
  "netbios-ssn": "NetBIOS session — use smbclient",
  "microsoft-ds": "SMB/CIFS share — use smbclient or mount",
  mysql: "MySQL — connect with the mysql client",
  "ms-sql-s": "MSSQL — connect with sqlcmd or DBeaver",
  postgresql: "PostgreSQL — connect with psql",
  redis: "Redis — connect with redis-cli",
  mongod: "MongoDB — connect with mongosh",
  "ms-wbt-server": "RDP — Remote Desktop client (xfreerdp, mstsc)",
  vnc: "VNC — use a VNC viewer (Remmina, RealVNC)",
  snmp: "SNMP — query with snmpwalk/snmpget",
  ldap: "LDAP — query with ldapsearch",
  ipp: "IPP printer — managed via CUPS/print dialog",
  nfs: "NFS — mount as filesystem",
  rtsp: "RTSP stream — open in VLC",
  realserver: "RealServer stream — open in VLC",
  rsync: "rsync — use the rsync client",
  ircd: "IRC server — use an IRC client",
};

function portHint(host, p) {
  if (p.state !== "open") return null;
  if (portUrl(host, p)) return null;
  const svc = (p.service || "").toLowerCase();
  if (svc && PORT_HINTS[svc]) return PORT_HINTS[svc];
  return "Not HTTP/HTTPS — needs a protocol-specific client";
}

function renderPortNumCell(host, p) {
  const label = `${p.port}/${escapeHtml(p.protocol)}`;
  const url = portUrl(host, p);
  const main = url
    ? `<a class="port-link" href="${escapeHtml(url)}" target="_blank" rel="noopener" title="Open ${escapeHtml(url)} in a new tab">${label} ↗</a>`
    : label;
  const hint = portHint(host, p);
  if (!hint) return main;
  return `${main}<div class="port-hint">${escapeHtml(hint)}</div>`;
}

function renderUdpStateCell(p) {
  const cls = udpStateClass(p.state);
  const label = udpStateLabel(p.state);
  const reason = p.state_reason || p.state;
  return `
    <span class="state-pill state-${cls}">${label}</span>
    <div class="state-reason">${escapeHtml(reason)}</div>`;
}

function renderUdpPortsTable(host) {
  const ports = host.udp_ports || [];
  if (!ports.length) {
    return `<div class="ports-empty">No UDP ports detected.</div>`;
  }
  const rows = ports
    .map(
      (p) => `
      <tr>
        <td class="port-num">${p.port}/udp</td>
        <td>${renderUdpStateCell(p)}</td>
        <td class="${p.service ? "" : "muted"}">${escapeHtml(p.service) || "—"}</td>
        <td class="${p.product ? "" : "muted"}">${escapeHtml(p.product) || "—"}</td>
        <td class="${p.version ? "" : "muted"}">${escapeHtml(p.version) || "—"}</td>
      </tr>`,
    )
    .join("");
  return `
    <table class="ports-table udp-ports-table">
      <thead>
        <tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderScriptBlock(s) {
  return `
    <div class="script-row">
      <span class="script-id">${escapeHtml(s.script_id)}</span>
      <pre class="script-output">${escapeHtml(s.output || "")}</pre>
    </div>`;
}

function renderHostScriptsBlock(host) {
  const scripts = host.host_scripts || [];
  if (!scripts.length) return "";
  return `
    <div class="host-scripts">
      <div class="host-scripts-title">Host scripts (${scripts.length})</div>
      ${scripts.map(renderScriptBlock).join("")}
    </div>`;
}

function renderPortRow(host, p) {
  const main = `
    <tr>
      <td class="port-num">${renderPortNumCell(host, p)}</td>
      <td>${renderPortStateCell(p)}</td>
      <td class="${p.service ? "" : "muted"}">${escapeHtml(p.service) || "—"}</td>
      <td class="${p.product ? "" : "muted"}">${escapeHtml(p.product) || "—"}</td>
      <td class="${p.version ? "" : "muted"}">${escapeHtml(p.version) || "—"}</td>
    </tr>`;
  const scripts = p.scripts || [];
  if (!scripts.length) return main;
  return `${main}
    <tr class="port-scripts-row">
      <td colspan="5">${scripts.map(renderScriptBlock).join("")}</td>
    </tr>`;
}

function renderPortsTable(host) {
  const ports = host.ports || [];
  if (!ports.length && !(host.host_scripts || []).length) {
    return `<div class="ports-empty">No accessible ports detected on top 100.</div>`;
  }
  const rows = ports.map((p) => renderPortRow(host, p)).join("");
  return `
    ${renderHostScriptsBlock(host)}
    <table class="ports-table">
      <thead>
        <tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderScan(scan) {
  lastScan = scan;
  els.empty.hidden = true;
  els.resultsHeader.hidden = false;
  els.deleteBtn.hidden = false;
  els.resultsCidr.textContent = scan.cidr;

  const upCount = scan.hosts.filter((h) => h.status === "up").length;
  const meta = [
    fmtTime(scan.started_at),
    fmtDuration(scan) ? `took ${fmtDuration(scan)}` : null,
    `${upCount} alive`,
    scan.status === "error" ? `error: ${scan.error_message}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
  els.resultsMeta.textContent = meta;

  if (!scan.hosts.length) {
    els.table.hidden = true;
    els.empty.hidden = false;
    els.empty.textContent =
      scan.status === "error"
        ? `Scan failed: ${scan.error_message || "unknown error"}`
        : "No hosts responded.";
    return;
  }

  els.table.hidden = false;
  els.body.innerHTML = scan.hosts.map(renderHostRow).join("");
  attachPortscanHandlers();
  attachOsscanHandlers();
  attachUdpscanHandlers();
  updateBulkButtons();
}

// ----- Bulk scans (v0.6.x): one button per scan kind in the results header.
// Each iterates the current scan's `up` hosts that haven't been scanned yet
// (the v0.2 limitation that prevents re-scan from the UI is preserved on
// purpose). Runs serially — 256 nmap processes in parallel would be a
// resource and traffic-collision problem. Reuses the per-host runX(hostId)
// functions so each row's button + sub-row update progressively.

let bulkRunning = null; // "ports" | "os" | "udp" | null
let bulkCancelRequested = false;

function eligibleHosts(kind) {
  if (!lastScan?.hosts) return [];
  const flag = kind === "ports" ? "portscanned_at"
            : kind === "os" ? "osscanned_at"
            : "udp_portscanned_at";
  return lastScan.hosts.filter((h) => h.status === "up" && !h[flag]);
}

function updateBulkButtons() {
  const buttons = [
    { btn: els.bulkPortscan, kind: "ports", label: "Scan all ports" },
    { btn: els.bulkOsscan,   kind: "os",    label: "Scan all OS" },
    { btn: els.bulkUdpscan,  kind: "udp",   label: "Scan all UDP" },
  ];
  for (const { btn, kind, label } of buttons) {
    if (!btn) continue;
    if (bulkRunning === kind) continue; // owner manages its own label/state
    btn.disabled = bulkRunning !== null;
    if (!lastScan) { btn.textContent = label; continue; }
    const remaining = eligibleHosts(kind).length;
    if (remaining === 0) {
      const upCount = lastScan.hosts.filter((h) => h.status === "up").length;
      btn.disabled = true;
      btn.textContent = upCount === 0 ? `${label} (no hosts)` : `${label} (all done)`;
    } else {
      btn.textContent = `${label} (${remaining})`;
    }
  }
}

async function runBulk(kind, runOne) {
  if (bulkRunning) return;
  const targets = eligibleHosts(kind);
  if (!targets.length) return;

  if (kind === "udp") {
    const minutes = Math.round(targets.length * 10);
    const ok = confirm(
      `UDP scans are slow — typically 5–15 min each.\n\n` +
      `${targets.length} host${targets.length === 1 ? "" : "s"} to scan ≈ ${minutes} minutes total.\n\n` +
      `Continue?`,
    );
    if (!ok) return;
  }

  bulkRunning = kind;
  bulkCancelRequested = false;
  const ownerBtn = kind === "ports" ? els.bulkPortscan
                : kind === "os" ? els.bulkOsscan
                : els.bulkUdpscan;
  const baseLabel = kind === "ports" ? "ports" : kind === "os" ? "OS" : "UDP";
  updateBulkButtons();

  let done = 0, failed = 0;
  const cancelHandler = () => { bulkCancelRequested = true; };
  ownerBtn.addEventListener("click", cancelHandler);

  const renderOwner = () => {
    ownerBtn.disabled = false;
    ownerBtn.textContent = `Cancel ${baseLabel} (${done}/${targets.length})`;
  };
  renderOwner();
  setStatus(`Bulk ${baseLabel} scan running — 0/${targets.length}…`);

  for (const host of targets) {
    if (bulkCancelRequested) break;
    try {
      await runOne(host.id);
    } catch (e) {
      failed++;
      console.error(`bulk ${kind} on host ${host.id} failed:`, e);
    }
    done++;
    renderOwner();
    setStatus(
      `Bulk ${baseLabel} — ${done}/${targets.length} done${failed ? ` · ${failed} failed` : ""}`,
    );
  }

  ownerBtn.removeEventListener("click", cancelHandler);
  bulkRunning = null;
  const tail = bulkCancelRequested ? " (canceled)" : "";
  setStatus(
    `Bulk ${baseLabel} finished — ${done}/${targets.length} done${failed ? ` · ${failed} failed` : ""}${tail}`,
  );
  bulkCancelRequested = false;
  updateBulkButtons();
}

function attachPortscanHandlers() {
  els.body.querySelectorAll(".portscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => onPortscanClick(parseInt(btn.dataset.hostId, 10)));
  });
}

function attachOsscanHandlers() {
  els.body.querySelectorAll(".osscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => onOsscanClick(parseInt(btn.dataset.hostId, 10)));
  });
}

function attachUdpscanHandlers() {
  els.body.querySelectorAll(".udpscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => onUdpscanClick(parseInt(btn.dataset.hostId, 10)));
  });
}

async function onPortscanClick(hostId) {
  const host = currentHostsById().get(hostId);
  if (!host) return;
  if (host.portscanned_at) {
    toggleHostDetail(hostId, "ports");
    return;
  }
  try { await runPortscan(hostId); } catch { /* setStatus already showed it */ }
}

async function onOsscanClick(hostId) {
  const host = currentHostsById().get(hostId);
  if (!host) return;
  if (host.osscanned_at) {
    toggleHostDetail(hostId, "os");
    return;
  }
  try { await runOsscan(hostId); } catch { /* setStatus already showed it */ }
}

async function onUdpscanClick(hostId) {
  const host = currentHostsById().get(hostId);
  if (!host) return;
  if (host.udp_portscanned_at) {
    toggleHostDetail(hostId, "udp");
    return;
  }
  if (!confirm("UDP scans are slow — top 100 typically takes 5–15 minutes. Continue?")) return;
  try { await runUdpscan(hostId); } catch { /* setStatus already showed it */ }
}

function currentHostsById() {
  // Walk visible rows and remember the host objects we last rendered.
  // We pull from the most recent `lastScan`.
  const m = new Map();
  if (lastScan?.hosts) for (const h of lastScan.hosts) m.set(h.id, h);
  return m;
}

let lastScan = null;

function toggleHostDetail(hostId, kind = "ports") {
  const detail = els.body.querySelector(
    `tr.host-detail[data-host-id="${hostId}"][data-kind="${kind}"]`,
  );
  if (!detail) return;
  detail.hidden = !detail.hidden;
}

async function runPortscan(hostId) {
  const btn = els.body.querySelector(`button.portscan-btn[data-host-id="${hostId}"]`);
  if (!btn) return;
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Scanning…";
  try {
    const timing = els.advTiming?.value || "T4";
    const scanType = els.advScanType?.value || "connect";
    const ports = currentPortsSpec();
    const scripts = currentScriptsSpec();
    const data = await fetchJson(`/api/hosts/${hostId}/portscan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timing, scanType, ports, scripts }),
    });
    if (lastScan) {
      const h = lastScan.hosts.find((x) => x.id === hostId);
      if (h) {
        h.ports = data.ports;
        h.host_scripts = data.host_scripts || [];
        h.portscanned_at = data.portscanned_at;
      }
    }
    const detail = els.body.querySelector(
      `tr.host-detail[data-host-id="${hostId}"][data-kind="ports"]`,
    );
    if (detail) {
      const host = lastScan?.hosts.find((x) => x.id === hostId);
      detail.querySelector("td").innerHTML = host ? renderPortsTable(host) : "";
      detail.hidden = false;
    }
    btn.innerHTML = portsButtonLabel(lastScan.hosts.find((x) => x.id === hostId));
    btn.disabled = false;
    updateBulkButtons();
  } catch (e) {
    btn.disabled = false;
    btn.textContent = original;
    setStatus(`Port scan failed: ${e.message}`, true);
    throw e;
  }
}

async function runUdpscan(hostId) {
  const btn = els.body.querySelector(`button.udpscan-btn[data-host-id="${hostId}"]`);
  if (!btn) return;
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Scanning UDP…";
  setStatus("UDP scan running — this can take several minutes.");
  try {
    const timing = els.advTiming?.value || "T4";
    const ports = currentPortsSpec();
    const data = await fetchJson(`/api/hosts/${hostId}/udp-portscan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timing, ports }),
    });
    if (lastScan) {
      const h = lastScan.hosts.find((x) => x.id === hostId);
      if (h) {
        h.udp_ports = data.udp_ports;
        h.udp_portscanned_at = data.udp_portscanned_at;
      }
    }
    const detail = els.body.querySelector(
      `tr.host-detail[data-host-id="${hostId}"][data-kind="udp"]`,
    );
    if (detail) {
      const host = lastScan?.hosts.find((x) => x.id === hostId);
      detail.querySelector("td").innerHTML = host ? renderUdpPortsTable(host) : "";
      detail.hidden = false;
    }
    btn.innerHTML = udpButtonLabel(lastScan.hosts.find((x) => x.id === hostId));
    btn.disabled = false;
    setStatus("UDP scan finished.");
    updateBulkButtons();
  } catch (e) {
    btn.disabled = false;
    btn.textContent = original;
    setStatus(`UDP scan failed: ${e.message}`, true);
    throw e;
  }
}

async function runOsscan(hostId) {
  const btn = els.body.querySelector(`button.osscan-btn[data-host-id="${hostId}"]`);
  if (!btn) return;
  btn.disabled = true;
  const original = btn.innerHTML;
  btn.textContent = "Scanning…";
  try {
    const data = await fetchJson(`/api/hosts/${hostId}/osscan`, { method: "POST" });
    if (lastScan) {
      const h = lastScan.hosts.find((x) => x.id === hostId);
      if (h) {
        h.os_matches = data.os_matches;
        h.osscanned_at = data.osscanned_at;
      }
    }
    const detail = els.body.querySelector(
      `tr.host-detail[data-host-id="${hostId}"][data-kind="os"]`,
    );
    if (detail) {
      const host = lastScan?.hosts.find((x) => x.id === hostId);
      detail.querySelector("td").innerHTML = host ? renderOsTable(host) : "";
      detail.hidden = false;
    }
    btn.innerHTML = osButtonLabel(lastScan.hosts.find((x) => x.id === hostId));
    btn.disabled = false;
    updateBulkButtons();
  } catch (e) {
    btn.disabled = false;
    btn.innerHTML = original;
    setStatus(`OS scan failed: ${e.message}`, true);
    throw e;
  }
}

async function runScan(cidr) {
  els.scanBtn.disabled = true;
  setStatus(`Scanning ${cidr}… this can take a few seconds.`);
  try {
    const discovery = currentDiscoverySpec();
    const scan = await fetchJson("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidr, discovery }),
    });
    activeScanId = scan.id;
    setStatus(`Done. ${scan.hosts.length} host${scan.hosts.length === 1 ? "" : "s"} responded.`);
    await loadHistory();
    renderScan(scan);
    document.querySelectorAll("#scan-list li").forEach((li) => {
      li.classList.toggle("active", parseInt(li.dataset.id, 10) === scan.id);
    });
  } catch (e) {
    setStatus(e.message, true);
    await loadHistory();
  } finally {
    els.scanBtn.disabled = false;
  }
}

els.form.addEventListener("submit", (e) => {
  e.preventDefault();
  const cidr = els.cidr.value.trim();
  if (!cidr) return;
  runScan(cidr);
});

els.bulkPortscan?.addEventListener("click", () => {
  if (bulkRunning === "ports") return; // click as Cancel is handled by inner listener
  if (bulkRunning) return;
  runBulk("ports", runPortscan);
});
els.bulkOsscan?.addEventListener("click", () => {
  if (bulkRunning === "os") return;
  if (bulkRunning) return;
  runBulk("os", runOsscan);
});
els.bulkUdpscan?.addEventListener("click", () => {
  if (bulkRunning === "udp") return;
  if (bulkRunning) return;
  runBulk("udp", runUdpscan);
});

// Theme toggle. The initial theme is applied inline in <head> to avoid
// a flash; this just keeps the button label in sync and persists clicks.
const themeBtn = document.getElementById("theme-toggle");
function syncThemeBtn() {
  if (!themeBtn) return;
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  themeBtn.textContent = isLight ? "Dark" : "Light";
}
syncThemeBtn();
themeBtn?.addEventListener("click", () => {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  if (isLight) {
    document.documentElement.removeAttribute("data-theme");
    try { localStorage.setItem("lanscope-theme", "dark"); } catch (_) {}
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    try { localStorage.setItem("lanscope-theme", "light"); } catch (_) {}
  }
  syncThemeBtn();
});

els.refresh.addEventListener("click", loadHistory);

els.clearHistory?.addEventListener("click", async () => {
  let scans = [];
  try {
    const res = await fetchJson("/api/scans?limit=200");
    scans = res.scans || [];
  } catch (e) {
    setStatus(e.message, true);
    return;
  }
  if (!scans.length) return;
  const ok = await confirmModal({
    title: "Clear all history",
    message: `${scans.length} scan${scans.length === 1 ? "" : "s"} and all their host data will be permanently removed.`,
    confirmText: "Delete all",
    danger: true,
  });
  if (!ok) return;
  els.clearHistory.disabled = true;
  const original = els.clearHistory.textContent;
  els.clearHistory.textContent = "Clearing…";
  const results = await Promise.allSettled(
    scans.map((s) => fetchJson(`/api/scans/${s.id}`, { method: "DELETE" })),
  );
  const failed = results.filter((r) => r.status === "rejected").length;
  activeScanId = null;
  lastScan = null;
  els.resultsHeader.hidden = true;
  els.deleteBtn.hidden = true;
  els.table.hidden = true;
  els.empty.hidden = false;
  els.empty.textContent = "Run a scan to see hosts here.";
  await loadHistory();
  els.clearHistory.disabled = false;
  els.clearHistory.textContent = original;
  if (failed) setStatus(`Cleared ${scans.length - failed}/${scans.length} scans · ${failed} failed`, true);
  else setStatus(`Cleared ${scans.length} scan${scans.length === 1 ? "" : "s"}.`);
});

// In-app confirm modal — replaces window.confirm so we control the look.
// Returns Promise<boolean>. Esc / backdrop / Cancel = false; Enter / Confirm = true.
function confirmModal({ title = "Confirm", message = "", confirmText = "Confirm", cancelText = "Cancel", danger = false } = {}) {
  return new Promise((resolve) => {
    const root = document.getElementById("modal-root");
    const titleEl = document.getElementById("modal-title");
    const msgEl = document.getElementById("modal-message");
    const okBtn = document.getElementById("modal-confirm");
    const cancelBtn = document.getElementById("modal-cancel");
    const backdrop = root.querySelector(".modal-backdrop");
    titleEl.textContent = title;
    msgEl.textContent = message;
    okBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;
    okBtn.classList.toggle("danger", !!danger);
    root.hidden = false;
    okBtn.focus();
    function cleanup(result) {
      root.hidden = true;
      okBtn.removeEventListener("click", onOk);
      cancelBtn.removeEventListener("click", onCancel);
      backdrop.removeEventListener("click", onCancel);
      document.removeEventListener("keydown", onKey);
      resolve(result);
    }
    function onOk() { cleanup(true); }
    function onCancel() { cleanup(false); }
    function onKey(e) {
      if (e.key === "Escape") { e.preventDefault(); cleanup(false); }
      else if (e.key === "Enter") { e.preventDefault(); cleanup(true); }
    }
    okBtn.addEventListener("click", onOk);
    cancelBtn.addEventListener("click", onCancel);
    backdrop.addEventListener("click", onCancel);
    document.addEventListener("keydown", onKey);
  });
}

els.deleteBtn.addEventListener("click", async () => {
  if (!activeScanId) return;
  const ok = await confirmModal({
    title: "Delete scan",
    message: "This scan and all its host data (ports, OS matches, scripts) will be permanently removed.",
    confirmText: "Delete",
    danger: true,
  });
  if (!ok) return;
  try {
    await fetchJson(`/api/scans/${activeScanId}`, { method: "DELETE" });
    activeScanId = null;
    lastScan = null;
    els.resultsHeader.hidden = true;
    els.deleteBtn.hidden = true;
    els.table.hidden = true;
    els.empty.hidden = false;
    els.empty.textContent = "Run a scan to see hosts here.";
    await loadHistory();
  } catch (e) {
    setStatus(e.message, true);
  }
});

loadHistory();
