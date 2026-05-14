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
  portFilterWrap: $("#port-filter-wrap"),
  portFilterInput: $("#port-filter-input"),
  portFilterToggle: $("#port-filter-toggle"),
  portFilterList: $("#port-filter-list"),
  viewToggle: $("#view-toggle"),
  viewTable: $("#view-table"),
  viewGraph: $("#view-graph"),
  graphWrap: $("#results-graph"),
  graphCanvas: $("#cy"),
  graphLegend: $("#graph-legend"),
  compareWrap: $("#compare-wrap"),
  compareBtn: $("#compare-btn"),
  compareList: $("#compare-list"),
  diffBanner: $("#diff-banner"),
  diffBannerText: $("#diff-banner-text"),
  diffExit: $("#diff-exit"),
  baselineBtn: $("#baseline-btn"),
  timelineBtn: $("#timeline-btn"),
  demoBanner: $("#demo-banner"),
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

let historyScans = [];

async function loadHistory() {
  try {
    const { scans } = await fetchJson("/api/scans");
    historyScans = scans || [];
    renderHistory(historyScans);
    refreshCompareDropdown();
    // Schedule rows reuse host_count from the matching scan in history, so
    // re-render them whenever history changes.
    if (schedules.length) renderSchedules();
    // v0.13.0 — any history change (new scan, delete, clear) may add or remove
    // alerts (ON DELETE CASCADE). Refresh the badge counter. Guarded with
    // typeof because the alerts module evaluates after the boot call to
    // loadHistory(); typeof avoids TDZ on first invocation.
    if (typeof refreshAlertBadge === "function") refreshAlertBadge();
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
    .map((s) => {
      const isBaseline = baselinesByCidr.get(s.cidr)?.scan_id === s.id;
      const star = isBaseline
        ? `<span class="scan-baseline-marker" title="Baseline for ${escapeHtml(s.cidr)}">★</span>`
        : "";
      const schedChip = scheduledScanChip(s);
      return `
      <li data-id="${s.id}" class="${s.id === activeScanId ? "active" : ""}${isBaseline ? " is-baseline" : ""}">
        <button class="scan-delete" data-id="${s.id}" title="Delete this scan" aria-label="Delete scan ${escapeHtml(s.cidr)}">×</button>
        <span class="scan-cidr">
          <span class="scan-status-dot ${s.status}"></span>${escapeHtml(s.cidr)}${star}${schedChip}
        </span>
        <span class="scan-meta">
          ${fmtTime(s.started_at)} · ${s.host_count} host${s.host_count === 1 ? "" : "s"}
        </span>
      </li>`;
    })
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
    if (typeof tlState !== "undefined" && tlState.active) closeTimeline({ silent: true });
    const scan = await fetchJson(`/api/scans/${id}`);
    activeScanId = id;
    compareSuppressed = false; // a fresh scan view re-enables baseline auto-compare
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

function diffStateFor(host) {
  if (!lastDiff || !host) return null;
  return lastDiff.byIp.get(host.ip) || null;
}

function diffReasonBadge(reasons) {
  if (!reasons || !reasons.length) return "";
  return ` <span class="diff-reason-badge" title="Fields that changed since the base scan">${reasons.join(", ")}</span>`;
}

function renderDisappearedRow(h) {
  return `
    <tr class="host-row diff-disappeared" data-disappeared-ip="${escapeHtml(h.ip)}">
      <td class="ip">${escapeHtml(h.ip)}</td>
      <td class="${h.mac ? "" : "muted"}">${escapeHtml(h.mac) || "—"}</td>
      <td class="${h.vendor ? "" : "muted"}">${escapeHtml(h.vendor) || "—"}</td>
      <td class="${h.hostname ? "" : "muted"}">${escapeHtml(h.hostname) || "—"}</td>
      <td class="muted">${escapeHtml(h.reason) || "—"}</td>
      <td class="muted">—</td>
      <td class="muted">—</td>
      <td class="muted">—</td>
    </tr>`;
}

function renderDisappearedSection() {
  if (!lastDiff || !lastDiff.disappeared.length) return "";
  const header = `
    <tr class="diff-section-header">
      <td colspan="8">Disappeared since base scan (${lastDiff.disappeared.length})</td>
    </tr>`;
  const rows = lastDiff.disappeared
    .slice()
    .sort((a, b) => compareIp(a.ip, b.ip))
    .map(renderDisappearedRow)
    .join("");
  return header + rows;
}

function renderHostRow(h) {
  const ds = diffStateFor(h);
  const rowClass = ds ? ` diff-${ds.state}` : "";
  const reasonBadge = ds && ds.state === "changed" ? diffReasonBadge(ds.reasons) : "";
  return `
    <tr class="host-row${rowClass}" data-host-id="${h.id}">
      <td class="ip">${escapeHtml(h.ip)}${reasonBadge}</td>
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

const RESCAN_FLAG_FOR_KIND = {
  ports: "portscanned_at",
  os: "osscanned_at",
  udp: "udp_portscanned_at",
};

const RESCAN_LABEL_FOR_KIND = {
  ports: "Re-scan ports",
  os: "Re-scan OS",
  udp: "Re-scan UDP",
};

function rescanToolbar(host, kind) {
  const ts = host[RESCAN_FLAG_FOR_KIND[kind]];
  const meta = ts ? `<span class="rescan-meta">last scan ${fmtTime(ts)}</span>` : "";
  return `
    <div class="rescan-toolbar">
      <button type="button" class="ghost small rescan-btn" data-host-id="${host.id}" data-kind="${kind}">${RESCAN_LABEL_FOR_KIND[kind]}</button>
      ${meta}
    </div>`;
}

function renderOsTable(host) {
  const matches = host.os_matches || [];
  const toolbar = rescanToolbar(host, "os");
  if (!matches.length) {
    return `${toolbar}<div class="ports-empty">No OS match (host fingerprint inconclusive).</div>`;
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
    ${toolbar}
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
  const toolbar = rescanToolbar(host, "udp");
  if (!ports.length) {
    return `${toolbar}<div class="ports-empty">No UDP ports detected.</div>`;
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
    ${toolbar}
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
  const toolbar = rescanToolbar(host, "ports");
  if (!ports.length && !(host.host_scripts || []).length) {
    return `${toolbar}<div class="ports-empty">No accessible ports detected on top 100.</div>`;
  }
  const rows = ports.map((p) => renderPortRow(host, p)).join("");
  return `
    ${toolbar}
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
  if (compareBaseScan && compareBaseScan.cidr !== scan.cidr) {
    compareBaseScan = null;
    compareBaseScanId = null;
    compareIsBaseline = false;
  }
  maybeApplyBaselineAutoCompare();
  recomputeDiff();
  renderDiffBanner();
  refreshCompareDropdown();
  refreshBaselineButton();
  els.empty.hidden = true;
  els.resultsHeader.hidden = false;
  els.deleteBtn.hidden = false;
  els.resultsCidr.textContent = scan.cidr;

  renderPortFilter(scan);
  const filtered = filterHosts(scan.hosts);
  const upCount = scan.hosts.filter((h) => h.status === "up").length;
  const meta = [
    fmtTime(scan.started_at),
    fmtDuration(scan) ? `took ${fmtDuration(scan)}` : null,
    `${upCount} alive`,
    filterPort !== null ? `${filtered.length} with port ${filterPort} open` : null,
    scan.status === "error" ? `error: ${scan.error_message}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
  els.resultsMeta.textContent = meta;

  if (!scan.hosts.length) {
    els.table.hidden = true;
    els.graphWrap.hidden = true;
    clearGraphCanvas();
    els.empty.hidden = false;
    els.empty.textContent =
      scan.status === "error"
        ? `Scan failed: ${scan.error_message || "unknown error"}`
        : "No hosts responded.";
    return;
  }

  els.body.innerHTML =
    sortHosts(filtered).map(renderHostRow).join("") +
    renderDisappearedSection();
  attachPortscanHandlers();
  attachOsscanHandlers();
  attachUdpscanHandlers();
  updateBulkButtons();

  if (viewMode === "graph") {
    els.table.hidden = true;
    els.empty.hidden = true;
    els.graphWrap.hidden = false;
    renderGraph(scan);
    if (cy) setTimeout(() => cy && cy.resize(), 0);
    return;
  }

  els.graphWrap.hidden = true;
  clearGraphCanvas();

  if (filterPort !== null && !filtered.length) {
    els.table.hidden = true;
    els.empty.hidden = false;
    els.empty.textContent = `No hosts have port ${filterPort} open. (Hosts not yet port-scanned are excluded.)`;
    return;
  }

  els.table.hidden = false;
}

// ----- Bulk scans (v0.6.x): one button per scan kind in the results header.
// Each iterates the current scan's `up` hosts that haven't been scanned yet
// (the v0.2 limitation that prevents re-scan from the UI is preserved on
// purpose). Runs serially — 256 nmap processes in parallel would be a
// resource and traffic-collision problem. Reuses the per-host runX(hostId)
// functions so each row's button + sub-row update progressively.

let bulkRunning = null; // "ports" | "os" | "udp" | null
let bulkCancelRequested = false;

function eligibleHosts(kind, force = false) {
  if (!lastScan?.hosts) return [];
  if (force) return lastScan.hosts.filter((h) => h.status === "up");
  const flag = RESCAN_FLAG_FOR_KIND[kind];
  return lastScan.hosts.filter((h) => h.status === "up" && !h[flag]);
}

function updateBulkButtons() {
  const buttons = [
    { btn: els.bulkPortscan, kind: "ports", label: "Scan all ports", rescanLabel: "Re-scan all ports" },
    { btn: els.bulkOsscan,   kind: "os",    label: "Scan all OS",    rescanLabel: "Re-scan all OS" },
    { btn: els.bulkUdpscan,  kind: "udp",   label: "Scan all UDP",   rescanLabel: "Re-scan all UDP" },
  ];
  for (const { btn, kind, label, rescanLabel } of buttons) {
    if (!btn) continue;
    if (bulkRunning === kind) continue; // owner manages its own label/state
    btn.disabled = bulkRunning !== null;
    btn.dataset.mode = "scan";
    if (!lastScan) { btn.textContent = label; continue; }
    const remaining = eligibleHosts(kind).length;
    const upCount = lastScan.hosts.filter((h) => h.status === "up").length;
    if (remaining === 0) {
      if (upCount === 0) {
        btn.disabled = true;
        btn.textContent = `${label} (no hosts)`;
      } else {
        btn.dataset.mode = "rescan";
        btn.textContent = `${rescanLabel} (${upCount})`;
      }
    } else {
      btn.textContent = `${label} (${remaining})`;
    }
  }
}

async function runBulk(kind, runOne, { force = false } = {}) {
  if (bulkRunning) return;
  const targets = eligibleHosts(kind, force);
  if (!targets.length) return;

  const kindLabel = kind === "ports" ? "TCP port" : kind === "os" ? "OS" : "UDP";
  if (force) {
    const udpNote = kind === "udp"
      ? `\n\nUDP scans are slow — top 100 typically takes 5–15 min per host (≈${Math.round(targets.length * 10)} min total).`
      : "";
    const ok = await confirmModal({
      title: `Re-scan all ${kindLabel}`,
      message: `This will replace existing ${kindLabel} data for ${targets.length} host${targets.length === 1 ? "" : "s"} in this scan.${udpNote}`,
      confirmText: "Re-scan",
      danger: true,
    });
    if (!ok) return;
  } else if (kind === "udp") {
    const minutes = Math.round(targets.length * 10);
    const ok = await confirmModal({
      title: "Scan all UDP",
      message: `UDP scans are slow — typically 5–15 min each.\n\n${targets.length} host${targets.length === 1 ? "" : "s"} to scan ≈ ${minutes} min total.`,
      confirmText: "Start",
    });
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
let sortState = { key: null, dir: null };

function compareIp(a, b) {
  const pa = (a || "").split(".").map((x) => parseInt(x, 10) || 0);
  const pb = (b || "").split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

function osBucket(host) {
  if (!host.osscanned_at) return null;
  const top = (host.os_matches || [])[0];
  if (!top) return null;
  const f = (top.family || "").toLowerCase();
  if (f.includes("windows")) return 1;
  if (f.includes("linux")) return 2;
  if (f.includes("mac") || f.includes("ios") || f.includes("apple")) return 3;
  return 4;
}

function osTopFamily(host) {
  const top = (host.os_matches || [])[0];
  return ((top && (top.family || top.name)) || "").toLowerCase();
}

function portsOpenCount(host) {
  if (!host.portscanned_at) return null;
  return (host.ports || []).filter((p) => p.state === "open").length;
}

const DEFAULT_SORT_DIR = { ip: "asc", vendor: "asc", os: "asc", ports: "desc" };

let filterPort = null;

function hasOpenPort(host, port) {
  if (!host.portscanned_at) return false;
  return (host.ports || []).some((p) => p.port === port && p.state === "open");
}

function filterHosts(hosts) {
  if (filterPort === null) return hosts;
  return hosts.filter((h) => hasOpenPort(h, filterPort));
}

function topOpenPorts(hosts, limit = 5) {
  const counts = new Map();
  for (const h of hosts) {
    if (!h.portscanned_at) continue;
    const seen = new Set();
    for (const p of h.ports || []) {
      if (p.state === "open" && !seen.has(p.port)) {
        seen.add(p.port);
        counts.set(p.port, (counts.get(p.port) || 0) + 1);
      }
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0] - b[0])
    .slice(0, limit)
    .map(([port, count]) => ({ port, count }));
}

function renderPortFilter(scan) {
  if (!els.portFilterWrap) return;
  const top = topOpenPorts(scan.hosts || [], 5);
  const anyScanned = (scan.hosts || []).some((h) => h.portscanned_at);
  if (!anyScanned) {
    els.portFilterWrap.hidden = true;
    els.portFilterList.hidden = true;
    if (filterPort !== null) filterPort = null;
    return;
  }
  els.portFilterWrap.hidden = false;
  els.portFilterInput.value = filterPort !== null ? String(filterPort) : "";
  if (!top.length) {
    els.portFilterList.innerHTML =
      `<li class="port-filter-empty">No open ports yet</li>`;
    return;
  }
  els.portFilterList.innerHTML = top
    .map(
      (t) =>
        `<li class="port-filter-item${
          t.port === filterPort ? " active" : ""
        }" data-port="${t.port}">${t.port} <span class="port-filter-count">· ${t.count} host${t.count === 1 ? "" : "s"}</span></li>`,
    )
    .join("");
}

function sortHosts(hosts) {
  if (!sortState.key) return hosts;
  const dir = sortState.dir === "desc" ? -1 : 1;
  return [...hosts].sort((a, b) => {
    if (sortState.key === "ip") return dir * compareIp(a.ip, b.ip);
    if (sortState.key === "vendor") {
      const va = (a.vendor || "").trim();
      const vb = (b.vendor || "").trim();
      if (!va && !vb) return 0;
      if (!va) return 1;
      if (!vb) return -1;
      return dir * va.localeCompare(vb, undefined, { sensitivity: "base" });
    }
    if (sortState.key === "os") {
      const ba = osBucket(a);
      const bb = osBucket(b);
      if (ba === null && bb === null) return 0;
      if (ba === null) return 1;
      if (bb === null) return -1;
      if (ba !== bb) return dir * (ba - bb);
      return dir * osTopFamily(a).localeCompare(osTopFamily(b));
    }
    if (sortState.key === "ports") {
      const ca = portsOpenCount(a);
      const cb = portsOpenCount(b);
      if (ca === null && cb === null) return 0;
      if (ca === null) return 1;
      if (cb === null) return -1;
      return dir * (ca - cb);
    }
    return 0;
  });
}

function updateSortIndicators() {
  document.querySelectorAll("#results-table thead th.sortable").forEach((th) => {
    th.classList.remove("sort-asc", "sort-desc");
    if (th.dataset.sortKey === sortState.key) {
      th.classList.add(sortState.dir === "desc" ? "sort-desc" : "sort-asc");
    }
  });
}

function attachSortHandlers() {
  document.querySelectorAll("#results-table thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (sortState.key === key) {
        sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
      } else {
        sortState.key = key;
        sortState.dir = DEFAULT_SORT_DIR[key] || "asc";
      }
      updateSortIndicators();
      if (lastScan) renderScan(lastScan);
    });
  });
}

/* ---------- topology graph (v0.7.0) ---------- */

let viewMode = localStorage.getItem("lanscope-view") || "table";
let cy = null;

function osBucketKey(host) {
  if (!host.osscanned_at) return "unknown";
  const top = (host.os_matches || [])[0];
  if (!top) return "unknown";
  const f = (top.family || "").toLowerCase();
  if (f.includes("windows")) return "windows";
  if (f.includes("linux")) return "linux";
  if (f.includes("mac") || f.includes("ios") || f.includes("apple")) return "apple";
  return "other";
}

const OS_LABELS = {
  windows: "Windows",
  linux: "Linux",
  apple: "Apple",
  other: "Other",
  unknown: "OS unknown",
};

function osBucketLabel(host) {
  const top = (host.os_matches || [])[0];
  if (top && top.family) return top.family;
  if (top && top.name) return top.name;
  return OS_LABELS[osBucketKey(host)];
}

function ipInCidr(ip, cidr) {
  const [base] = cidr.split("/");
  const baseParts = base.split(".").map((x) => parseInt(x, 10));
  const ipParts = ip.split(".").map((x) => parseInt(x, 10));
  return (
    baseParts.length === 4 &&
    ipParts.length === 4 &&
    baseParts[0] === ipParts[0] &&
    baseParts[1] === ipParts[1] &&
    baseParts[2] === ipParts[2]
  );
}

function findGateway(scan) {
  const hosts = (scan.hosts || []).filter((h) => h.status === "up");
  if (!hosts.length) return null;
  const cidr = scan.cidr || "";
  const candidates = [];
  if (cidr) {
    const baseParts = cidr.split("/")[0].split(".").map((x) => parseInt(x, 10));
    if (baseParts.length === 4) {
      candidates.push(`${baseParts[0]}.${baseParts[1]}.${baseParts[2]}.1`);
      candidates.push(`${baseParts[0]}.${baseParts[1]}.${baseParts[2]}.254`);
    }
  }
  for (const c of candidates) {
    const found = hosts.find((h) => h.ip === c);
    if (found) return found;
  }
  return null;
}

function openPortCount(host) {
  if (!host.portscanned_at) return null;
  return (host.ports || []).filter((p) => p.state === "open").length;
}

function nodeLabelFor(host, isGateway) {
  const lines = [host.ip];
  if (host.hostname) lines.push(host.hostname);
  const ports = openPortCount(host);
  const hasOs = !!host.osscanned_at && (host.os_matches || []).length > 0;
  if (hasOs && ports !== null) {
    lines.push(`${osBucketLabel(host)} · ${ports} port${ports === 1 ? "" : "s"}`);
  } else if (hasOs) {
    lines.push(osBucketLabel(host));
  } else if (ports !== null) {
    lines.push(`${ports} port${ports === 1 ? "" : "s"} open`);
  }
  if (isGateway) lines.push("gateway");
  return lines.join("\n");
}

function hostRelevance(host, isGateway) {
  if (isGateway) return 5;
  const hasOs = !!host.osscanned_at && (host.os_matches || []).length > 0;
  const ports = openPortCount(host);
  const hasOpenPorts = ports !== null && ports > 0;
  if (hasOs && hasOpenPorts) return 4;
  if (hasOs || hasOpenPorts) return 3;
  if (host.portscanned_at || host.osscanned_at || host.udp_portscanned_at) return 2;
  if (host.hostname || host.vendor) return 2;
  return 1;
}

function readThemePalette() {
  const cs = getComputedStyle(document.documentElement);
  const v = (name, fallback) => (cs.getPropertyValue(name) || fallback).trim();
  return {
    text: v("--text", "#ffffff"),
    textMute: v("--text-mute", "#909090"),
    accent: v("--accent", "#22c55e"),
    accentStrong: v("--accent-strong", "#16a34a"),
    surface: v("--surface", "#131313"),
    surface2: v("--surface-2", "#1c1c1c"),
    border: v("--border-strong", "#353535"),
    accentFg: v("--accent-fg", "#ffffff"),
    bucket: {
      windows: "#2563eb",
      linux:   "#d97706",
      apple:   "#7c3aed",
      other:   "#64748b",
      unknown: "#475569",
    },
  };
}

function buildGraphElements(scan, gateway) {
  const hosts = (scan.hosts || []).filter((h) => h.status === "up");
  const elements = [];
  const gatewayId = gateway ? `host-${gateway.id}` : null;
  for (const h of hosts) {
    const isGw = gateway && h.id === gateway.id;
    const ds = diffStateFor(h);
    elements.push({
      group: "nodes",
      data: {
        id: `host-${h.id}`,
        hostId: h.id,
        label: nodeLabelFor(h, isGw),
        bucket: osBucketKey(h),
        isGateway: isGw ? 1 : 0,
        relevance: hostRelevance(h, isGw),
        diff: ds ? ds.state : "",
      },
    });
  }
  if (lastDiff && lastDiff.disappeared.length) {
    for (const h of lastDiff.disappeared) {
      elements.push({
        group: "nodes",
        data: {
          id: `disappeared-${h.ip.replace(/\./g, "-")}`,
          label: `${h.ip}${h.hostname ? `\n${h.hostname}` : ""}\ndisappeared`,
          bucket: osBucketKey(h),
          isGateway: 0,
          relevance: 1,
          diff: "disappeared",
        },
      });
    }
  }
  if (gatewayId) {
    for (const h of hosts) {
      if (h.id === gateway.id) continue;
      elements.push({
        group: "edges",
        data: {
          id: `e-${h.id}`,
          source: `host-${h.id}`,
          target: gatewayId,
          relevance: hostRelevance(h, false),
        },
      });
    }
  }
  return elements;
}

function renderGraphLegend(scan, hadGateway, palette) {
  const hosts = (scan.hosts || []).filter((h) => h.status === "up");
  const present = new Set(hosts.map(osBucketKey));
  const order = ["windows", "linux", "apple", "other", "unknown"];
  const items = order
    .filter((b) => present.has(b))
    .map(
      (b) =>
        `<span class="graph-legend-item"><span class="graph-legend-swatch" style="background:${palette.bucket[b]}"></span>${OS_LABELS[b]}</span>`,
    );
  if (hadGateway) {
    items.unshift(
      `<span class="graph-legend-item"><span class="graph-legend-swatch" style="background:${palette.accent}"></span>Gateway</span>`,
    );
  }
  if (diffActive() && lastDiff) {
    if (lastDiff.appeared.length) {
      items.push(`<span class="graph-legend-item"><span class="graph-legend-swatch" style="background:transparent;border-color:#22c55e;border-width:2px"></span>Appeared</span>`);
    }
    if (lastDiff.changed.length) {
      items.push(`<span class="graph-legend-item"><span class="graph-legend-swatch" style="background:transparent;border-color:#facc15;border-width:2px"></span>Changed</span>`);
    }
    if (lastDiff.disappeared.length) {
      items.push(`<span class="graph-legend-item"><span class="graph-legend-swatch" style="background:transparent;border-color:#ef4444;border-width:2px;border-style:dashed"></span>Disappeared</span>`);
    }
  }
  els.graphLegend.innerHTML = items.join("");
  els.graphLegend.hidden = items.length === 0;
}

function clearGraphCanvas() {
  if (cy) {
    cy.destroy();
    cy = null;
  }
  els.graphCanvas.innerHTML = "";
}

function showGraphEmpty(message) {
  clearGraphCanvas();
  const div = document.createElement("div");
  div.className = "graph-empty";
  div.textContent = message;
  els.graphCanvas.appendChild(div);
  els.graphLegend.hidden = true;
  els.graphLegend.innerHTML = "";
}

function renderGraph(scan) {
  if (typeof cytoscape === "undefined") {
    showGraphEmpty("Graph library failed to load. Check your network and refresh.");
    return;
  }
  const hosts = (scan.hosts || []).filter((h) => h.status === "up");
  if (!hosts.length) {
    showGraphEmpty("No alive hosts in this scan to graph.");
    return;
  }
  const gateway = findGateway(scan);
  const elements = buildGraphElements(scan, gateway);
  const palette = readThemePalette();

  clearGraphCanvas();

  cy = cytoscape({
    container: els.graphCanvas,
    elements,
    wheelSensitivity: 0.25,
    style: [
      {
        selector: "node",
        style: {
          shape: "round-rectangle",
          "background-color": (ele) =>
            ele.data("isGateway") ? palette.accent : palette.bucket[ele.data("bucket")],
          "border-color": palette.border,
          "border-width": 1,
          width: 90,
          height: 46,
          label: "data(label)",
          color: (ele) => (ele.data("isGateway") ? palette.accentFg : "#ffffff"),
          "text-wrap": "wrap",
          "text-max-width": 84,
          "text-valign": "center",
          "text-halign": "center",
          "font-family": "JetBrains Mono, Fira Code, ui-monospace, monospace",
          "font-size": 8.5,
          "font-weight": 600,
          "line-height": 1.2,
        },
      },
      {
        selector: "node[relevance < 3]",
        style: {
          width: 70,
          height: 24,
          "font-size": 8,
          opacity: 0.85,
        },
      },
      {
        selector: "node[isGateway = 1]",
        style: {
          shape: "diamond",
          width: 130,
          height: 80,
          "font-size": 10,
        },
      },
      {
        selector: "node:selected",
        style: {
          "border-color": palette.accent,
          "border-width": 3,
        },
      },
      {
        selector: 'node[diff = "appeared"]',
        style: { "border-color": "#22c55e", "border-width": 3 },
      },
      {
        selector: 'node[diff = "changed"]',
        style: { "border-color": "#facc15", "border-width": 3 },
      },
      {
        selector: 'node[diff = "disappeared"]',
        style: {
          "background-color": palette.surface2,
          "border-color": "#ef4444",
          "border-width": 2,
          "border-style": "dashed",
          opacity: 0.45,
          color: palette.textMute,
        },
      },
      {
        selector: "edge",
        style: {
          width: 1,
          "line-color": palette.border,
          "curve-style": "straight",
          opacity: 0.6,
        },
      },
      {
        selector: "edge[relevance < 3]",
        style: {
          opacity: 0.2,
          width: 0.6,
        },
      },
    ],
    layout: gateway
      ? {
          name: "concentric",
          concentric: (n) => n.data("relevance"),
          levelWidth: () => 1,
          minNodeSpacing: 8,
          spacingFactor: 1.05,
          avoidOverlap: true,
          padding: 30,
        }
      : { name: "cose", padding: 30, animate: false, nodeRepulsion: 4500 },
  });

  cy.on("tap", "node", (evt) => {
    const hostId = evt.target.data("hostId");
    if (hostId !== undefined) selectHostFromGraph(hostId);
  });

  renderGraphLegend(scan, !!gateway, palette);
}

function selectHostFromGraph(hostId) {
  setViewMode("table");
  requestAnimationFrame(() => {
    const row = els.body.querySelector(`tr.host-row[data-host-id="${hostId}"]`);
    if (!row) return;
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.classList.remove("row-flash");
    void row.offsetWidth;
    row.classList.add("row-flash");
    setTimeout(() => row.classList.remove("row-flash"), 1600);
  });
}

function setViewMode(mode) {
  viewMode = mode === "graph" ? "graph" : "table";
  localStorage.setItem("lanscope-view", viewMode);
  els.viewTable.classList.toggle("active", viewMode === "table");
  els.viewGraph.classList.toggle("active", viewMode === "graph");
  els.viewTable.setAttribute("aria-selected", viewMode === "table" ? "true" : "false");
  els.viewGraph.setAttribute("aria-selected", viewMode === "graph" ? "true" : "false");
  if (lastScan) renderScan(lastScan);
}

/* ---------- diff between scans (v0.7.1) ---------- */

let compareBaseScan = null;     // full Scan object loaded for comparison
let compareBaseScanId = null;   // id of the base scan (kept for cheap equality)
let lastDiff = null;            // { appeared, disappeared, changed, byIp }
let compareIsBaseline = false;  // true when compareBaseScan came from inventory baseline auto-compare
let compareSuppressed = false;  // user exited diff for the current scan view; cleared on loadScan
let baselinesByCidr = new Map();// cidr -> { cidr, scan_id, set_at, started_at, host_count }
let baselineAutoFetching = null; // in-flight scan id for the baseline being loaded (race guard)

function hostChangeReasons(b, n) {
  const reasons = [];
  if ((b.mac || "") !== (n.mac || "")) reasons.push("mac");
  if ((b.hostname || "") !== (n.hostname || "")) reasons.push("hostname");
  if (b.osscanned_at && n.osscanned_at) {
    const bk = osBucketKey(b);
    const nk = osBucketKey(n);
    if (bk !== nk && bk !== "unknown" && nk !== "unknown") reasons.push("os");
  }
  return reasons;
}

function diffScans(baseScan, newScan) {
  const baseUp = (baseScan?.hosts || []).filter((h) => h.status === "up");
  const newUp  = (newScan?.hosts  || []).filter((h) => h.status === "up");
  const baseByIp = new Map(baseUp.map((h) => [h.ip, h]));
  const newByIp  = new Map(newUp.map((h) => [h.ip, h]));
  const appeared = [];
  const disappeared = [];
  const changed = [];
  const unchanged = [];
  const byIp = new Map(); // ip -> { state, reasons? }
  for (const n of newUp) {
    const b = baseByIp.get(n.ip);
    if (!b) {
      appeared.push(n);
      byIp.set(n.ip, { state: "appeared" });
    } else {
      const reasons = hostChangeReasons(b, n);
      if (reasons.length) {
        changed.push({ host: n, base: b, reasons });
        byIp.set(n.ip, { state: "changed", reasons });
      } else {
        unchanged.push(n);
        byIp.set(n.ip, { state: "unchanged" });
      }
    }
  }
  for (const b of baseUp) {
    if (!newByIp.has(b.ip)) {
      disappeared.push(b);
      byIp.set(b.ip, { state: "disappeared" });
    }
  }
  return { appeared, disappeared, changed, unchanged, byIp };
}

function diffActive() {
  return !!(compareBaseScan && lastScan && compareBaseScan.cidr === lastScan.cidr && compareBaseScan.id !== lastScan.id);
}

function recomputeDiff() {
  lastDiff = diffActive() ? diffScans(compareBaseScan, lastScan) : null;
}

function exitDiff() {
  compareBaseScan = null;
  compareBaseScanId = null;
  compareIsBaseline = false;
  lastDiff = null;
  compareSuppressed = true;
  if (els.compareList) els.compareList.hidden = true;
  refreshCompareDropdown();
  if (lastScan) renderScan(lastScan);
}

/* ---------- inventory baselines (v0.8.0) ---------- */

async function loadBaselines() {
  try {
    const { baselines } = await fetchJson("/api/inventory");
    baselinesByCidr = new Map((baselines || []).map((b) => [b.cidr, b]));
  } catch (e) {
    console.error("loadBaselines failed:", e);
    baselinesByCidr = new Map();
  }
  refreshBaselineButton();
  if (historyScans.length) renderHistory(historyScans);
}

function refreshBaselineButton() {
  if (els.timelineBtn) els.timelineBtn.hidden = !lastScan;
  if (!els.baselineBtn) return;
  if (!lastScan) {
    els.baselineBtn.hidden = true;
    return;
  }
  els.baselineBtn.hidden = false;
  const baseline = baselinesByCidr.get(lastScan.cidr);
  const isThisOne = baseline && baseline.scan_id === lastScan.id;
  if (isThisOne) {
    els.baselineBtn.textContent = "★ Unset baseline";
    els.baselineBtn.classList.add("active");
    els.baselineBtn.title = `This scan is the baseline for ${lastScan.cidr}. Click to unset.`;
  } else {
    els.baselineBtn.textContent = baseline ? "★ Make this the baseline" : "★ Set as baseline";
    els.baselineBtn.classList.remove("active");
    els.baselineBtn.title = baseline
      ? `Replace the existing baseline for ${lastScan.cidr} with this scan.`
      : `Mark this scan as the baseline for ${lastScan.cidr}. Future scans of the same CIDR will be compared against it automatically.`;
  }
}

async function toggleBaseline() {
  if (!lastScan) return;
  const baseline = baselinesByCidr.get(lastScan.cidr);
  const isThisOne = baseline && baseline.scan_id === lastScan.id;
  try {
    if (isThisOne) {
      await fetchJson(`/api/inventory/${encodeURIComponent(lastScan.cidr)}`, { method: "DELETE" });
      setStatus(`Baseline cleared for ${lastScan.cidr}.`);
      if (compareIsBaseline) {
        compareBaseScan = null;
        compareBaseScanId = null;
        compareIsBaseline = false;
        lastDiff = null;
      }
    } else {
      await fetchJson("/api/inventory", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: lastScan.id }),
      });
      setStatus(`This scan is now the baseline for ${lastScan.cidr}.`);
      // If we were auto-comparing against an old baseline, drop it; the new
      // baseline is this scan itself, so there's nothing to compare against here.
      if (compareIsBaseline) {
        compareBaseScan = null;
        compareBaseScanId = null;
        compareIsBaseline = false;
        lastDiff = null;
      }
    }
    await loadBaselines();
    if (lastScan) renderScan(lastScan);
  } catch (e) {
    setStatus(`Baseline update failed: ${e.message}`, true);
  }
}

function maybeApplyBaselineAutoCompare() {
  if (!lastScan) return;
  if (compareBaseScan) return;          // already comparing (manual or baseline-loaded)
  if (compareSuppressed) return;        // user exited diff for this view
  const baseline = baselinesByCidr.get(lastScan.cidr);
  if (!baseline) return;
  if (baseline.scan_id === lastScan.id) return; // viewing the baseline itself
  if (baselineAutoFetching === baseline.scan_id) return; // already fetching
  baselineAutoFetching = baseline.scan_id;
  const targetCidr = lastScan.cidr;
  fetchJson(`/api/scans/${baseline.scan_id}`)
    .then((scan) => {
      baselineAutoFetching = null;
      // Race-guard: discard if the user moved on to another scan or already
      // picked a manual base while the fetch was in flight.
      if (!lastScan || lastScan.cidr !== targetCidr) return;
      if (compareBaseScan) return;
      if (compareSuppressed) return;
      compareBaseScan = scan;
      compareBaseScanId = scan.id;
      compareIsBaseline = true;
      renderScan(lastScan);
    })
    .catch((e) => {
      baselineAutoFetching = null;
      console.error("baseline auto-compare fetch failed:", e);
    });
}

function comparableScans() {
  if (!lastScan) return [];
  return historyScans.filter(
    (s) => s.cidr === lastScan.cidr && s.id !== lastScan.id && s.status === "done",
  );
}

function refreshCompareDropdown() {
  if (!els.compareWrap) return;
  const options = comparableScans();
  els.compareWrap.hidden = options.length === 0 && !diffActive();
  if (els.compareBtn) {
    if (diffActive()) {
      els.compareBtn.textContent = "Change base…";
      els.compareBtn.classList.add("active");
    } else {
      els.compareBtn.textContent = options.length
        ? `Compare with… (${options.length})`
        : "Compare with…";
      els.compareBtn.classList.remove("active");
    }
    els.compareBtn.disabled = options.length === 0;
  }
  if (els.compareList) {
    if (!options.length) {
      els.compareList.innerHTML = `<li class="compare-empty">No earlier scans for ${escapeHtml(lastScan?.cidr || "")}</li>`;
      return;
    }
    const items = options.map((s) => {
      const active = s.id === compareBaseScanId ? " active" : "";
      const meta = `${fmtTime(s.started_at)}${s.host_count != null ? ` · ${s.host_count} alive` : ""}`;
      return `<li class="compare-item${active}" data-scan-id="${s.id}">${escapeHtml(meta)}</li>`;
    });
    els.compareList.innerHTML = items.join("");
  }
}

function renderDiffBanner() {
  if (!els.diffBanner) return;
  if (!diffActive() || !lastDiff) {
    els.diffBanner.hidden = true;
    els.diffBannerText.textContent = "";
    els.diffBanner.classList.remove("baseline");
    return;
  }
  const baseTime = fmtTime(compareBaseScan.started_at);
  const header = compareIsBaseline
    ? `<strong>★ Compared against baseline</strong> (set from ${baseTime})`
    : `Comparing with scan from ${baseTime}`;
  const parts = [
    header,
    `<strong class="diff-c-appeared">${lastDiff.appeared.length} appeared</strong>`,
    `<strong class="diff-c-disappeared">${lastDiff.disappeared.length} disappeared</strong>`,
    `<strong class="diff-c-changed">${lastDiff.changed.length} changed</strong>`,
  ];
  els.diffBanner.hidden = false;
  els.diffBanner.classList.toggle("baseline", compareIsBaseline);
  els.diffBannerText.innerHTML = parts.join(" · ");
}

async function setCompareBase(scanId) {
  try {
    const scan = await fetchJson(`/api/scans/${scanId}`);
    if (!lastScan || scan.cidr !== lastScan.cidr) {
      setStatus("Cannot compare: scans are for different CIDRs.", true);
      return;
    }
    compareBaseScan = scan;
    compareBaseScanId = scan.id;
    compareIsBaseline = false; // manual selection overrides any baseline auto-compare
    compareSuppressed = false;
    if (els.compareList) els.compareList.hidden = true;
    refreshCompareDropdown();
    renderScan(lastScan);
  } catch (e) {
    setStatus(`Failed to load comparison scan: ${e.message}`, true);
  }
}

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
  const rescanBtn = els.body.querySelector(
    `button.rescan-btn[data-host-id="${hostId}"][data-kind="ports"]`,
  );
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Scanning…";
  if (rescanBtn) { rescanBtn.disabled = true; rescanBtn.textContent = "Re-scanning…"; }
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
    if (rescanBtn) { rescanBtn.disabled = false; rescanBtn.textContent = RESCAN_LABEL_FOR_KIND.ports; }
    setStatus(`Port scan failed: ${e.message}`, true);
    throw e;
  }
}

async function runUdpscan(hostId) {
  const btn = els.body.querySelector(`button.udpscan-btn[data-host-id="${hostId}"]`);
  if (!btn) return;
  const rescanBtn = els.body.querySelector(
    `button.rescan-btn[data-host-id="${hostId}"][data-kind="udp"]`,
  );
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Scanning UDP…";
  if (rescanBtn) { rescanBtn.disabled = true; rescanBtn.textContent = "Re-scanning UDP…"; }
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
    if (rescanBtn) { rescanBtn.disabled = false; rescanBtn.textContent = RESCAN_LABEL_FOR_KIND.udp; }
    setStatus(`UDP scan failed: ${e.message}`, true);
    throw e;
  }
}

async function runOsscan(hostId) {
  const btn = els.body.querySelector(`button.osscan-btn[data-host-id="${hostId}"]`);
  if (!btn) return;
  const rescanBtn = els.body.querySelector(
    `button.rescan-btn[data-host-id="${hostId}"][data-kind="os"]`,
  );
  btn.disabled = true;
  const original = btn.innerHTML;
  btn.textContent = "Scanning…";
  if (rescanBtn) { rescanBtn.disabled = true; rescanBtn.textContent = "Re-scanning…"; }
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
    if (rescanBtn) { rescanBtn.disabled = false; rescanBtn.textContent = RESCAN_LABEL_FOR_KIND.os; }
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
  const force = els.bulkPortscan.dataset.mode === "rescan";
  runBulk("ports", runPortscan, { force });
});
els.bulkOsscan?.addEventListener("click", () => {
  if (bulkRunning === "os") return;
  if (bulkRunning) return;
  const force = els.bulkOsscan.dataset.mode === "rescan";
  runBulk("os", runOsscan, { force });
});
els.bulkUdpscan?.addEventListener("click", () => {
  if (bulkRunning === "udp") return;
  if (bulkRunning) return;
  const force = els.bulkUdpscan.dataset.mode === "rescan";
  runBulk("udp", runUdpscan, { force });
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
  if (viewMode === "graph" && lastScan) {
    setTimeout(() => renderGraph(lastScan), 260);
  }
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

attachSortHandlers();

els.portFilterToggle?.addEventListener("click", (e) => {
  e.stopPropagation();
  if (!els.portFilterList) return;
  els.portFilterList.hidden = !els.portFilterList.hidden;
});

els.portFilterList?.addEventListener("click", (e) => {
  const item = e.target.closest(".port-filter-item");
  if (!item) return;
  const port = parseInt(item.dataset.port, 10);
  if (isNaN(port)) return;
  filterPort = port;
  els.portFilterList.hidden = true;
  if (lastScan) renderScan(lastScan);
});

els.portFilterInput?.addEventListener("input", () => {
  const v = els.portFilterInput.value.trim();
  const n = parseInt(v, 10);
  filterPort = v === "" || isNaN(n) || n < 1 || n > 65535 ? null : n;
  if (lastScan) renderScan(lastScan);
});

els.portFilterInput?.addEventListener("focus", () => {
  if (els.portFilterList) els.portFilterList.hidden = false;
});

document.addEventListener("click", (e) => {
  if (!els.portFilterWrap || els.portFilterWrap.hidden) return;
  if (els.portFilterList?.hidden) return;
  if (!els.portFilterWrap.contains(e.target)) {
    els.portFilterList.hidden = true;
  }
});

els.viewTable?.addEventListener("click", () => setViewMode("table"));
els.viewGraph?.addEventListener("click", () => setViewMode("graph"));

els.compareBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  if (!els.compareList) return;
  refreshCompareDropdown();
  els.compareList.hidden = !els.compareList.hidden;
});

els.compareList?.addEventListener("click", (e) => {
  const item = e.target.closest(".compare-item");
  if (!item) return;
  const scanId = parseInt(item.dataset.scanId, 10);
  if (!Number.isNaN(scanId)) setCompareBase(scanId);
});

els.diffExit?.addEventListener("click", exitDiff);

els.baselineBtn?.addEventListener("click", toggleBaseline);

document.addEventListener("click", (e) => {
  if (!els.compareWrap || els.compareWrap.hidden) return;
  if (els.compareList?.hidden) return;
  if (!els.compareWrap.contains(e.target)) {
    els.compareList.hidden = true;
  }
});

els.body.addEventListener("click", async (e) => {
  const btn = e.target.closest(".rescan-btn");
  if (!btn || btn.disabled) return;
  const hostId = parseInt(btn.dataset.hostId, 10);
  const kind = btn.dataset.kind;
  if (Number.isNaN(hostId)) return;
  if (kind === "udp") {
    const ok = await confirmModal({
      title: "Re-scan UDP",
      message: "UDP scans are slow — top 100 typically takes 5–15 minutes. This will replace the existing UDP data for this host.",
      confirmText: "Re-scan",
    });
    if (!ok) return;
    runUdpscan(hostId).catch(() => {});
    return;
  }
  if (kind === "ports") { runPortscan(hostId).catch(() => {}); return; }
  if (kind === "os")    { runOsscan(hostId).catch(() => {});    return; }
});

setViewMode(viewMode);

window.addEventListener("resize", () => {
  if (cy) cy.resize();
});

// v0.10.0 — scheduled scans UI

const schedEls = {
  list: document.getElementById("schedule-list"),
  newBtn: document.getElementById("new-schedule-btn"),
  refreshBtn: document.getElementById("refresh-schedules"),
  modal: document.getElementById("modal-schedule"),
  modalForm: document.getElementById("sched-modal-form"),
  modalError: document.getElementById("sched-modal-error"),
  modalCreate: document.getElementById("sched-modal-create"),
  inputName: document.getElementById("sched-name"),
  inputCidr: document.getElementById("sched-cidr"),
  inputCron: document.getElementById("sched-cron"),
  cronPresets: Array.from(document.querySelectorAll(".cron-preset")),
  cronHint: document.getElementById("sched-cron-hint"),
};

let schedules = [];
let schedulesById = new Map();

const CRON_PRESET_LABELS = {
  "*/15 * * * *": "Every 15 minutes",
  "0 * * * *": "Every hour",
  "0 */3 * * *": "Every 3 hours",
  "0 3 * * *": "Daily at 3:00 AM",
};

function cronHumanLabel(expr) {
  return CRON_PRESET_LABELS[expr] || `Custom — ${expr}`;
}

function scheduledScanChip(scan) {
  if (!scan.schedule_id) return "";
  const sched = schedulesById.get(scan.schedule_id);
  const tip = sched ? `Scheduled by: ${sched.name}` : "Scheduled scan";
  return ` <span class="scan-scheduled-chip" title="${escapeHtml(tip)}">⏱</span>`;
}

function fmtClock(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function lastRunSummary(s) {
  if (!s.last_run_at) {
    return `<span class="schedule-lastrun muted">Never run yet</span>`;
  }
  const ts = fmtClock(s.last_run_at);
  if (s.last_status === "done") {
    const scan = historyScans.find((x) => x.id === s.last_scan_id);
    const hostStr = scan ? ` · ${scan.host_count} host${scan.host_count === 1 ? "" : "s"}` : "";
    return `<span class="schedule-lastrun done" title="Last successful run">✓ ${ts}${hostStr}</span>`;
  }
  if (s.last_status === "error") {
    const tip = s.last_error ? `Error: ${s.last_error}` : "Error";
    return `<span class="schedule-lastrun error" title="${escapeHtml(tip)}">✗ ${ts} · error</span>`;
  }
  if (s.last_status === "skipped") {
    const tip = s.last_error || "Another scan was running at the time";
    return `<span class="schedule-lastrun skipped" title="${escapeHtml(tip)}">⊘ ${ts} · skipped</span>`;
  }
  return `<span class="schedule-lastrun">${ts}</span>`;
}

async function loadSchedules() {
  try {
    const { schedules: rows } = await fetchJson("/api/schedules");
    schedules = rows || [];
    schedulesById = new Map(schedules.map((s) => [s.id, s]));
    renderSchedules();
    // History rows show the ⏱ chip + tooltip with schedule name; refresh
    // them so the tooltip text matches the latest schedule data.
    if (historyScans.length) renderHistory(historyScans);
  } catch (e) {
    console.error("loadSchedules failed:", e);
  }
}

function renderScheduleRow(s) {
  const checkedAttr = s.enabled ? "checked" : "";
  return `
    <li class="${s.enabled ? "" : "disabled"}" data-id="${s.id}">
      <span class="schedule-name">${escapeHtml(s.name)}</span>
      <span class="schedule-meta"><code>${escapeHtml(s.cidr)}</code> · ${escapeHtml(cronHumanLabel(s.cron_expr))}</span>
      ${lastRunSummary(s)}
      <div class="schedule-controls">
        <button class="ghost small sched-run" data-act="run" data-id="${s.id}" title="Run this scan now">▶ Run now</button>
        <label class="sched-toggle" title="Enable or disable this schedule">
          <input type="checkbox" data-act="toggle" data-id="${s.id}" ${checkedAttr} />
          <span>${s.enabled ? "On" : "Off"}</span>
        </label>
        <button class="sched-delete" data-act="delete" data-id="${s.id}" title="Delete schedule" aria-label="Delete schedule">×</button>
      </div>
    </li>`;
}

function renderSchedules() {
  if (!schedules.length) {
    schedEls.list.innerHTML = `<li class="muted">No schedules yet.</li>`;
    return;
  }
  schedEls.list.innerHTML = schedules.map(renderScheduleRow).join("");
  schedEls.list.querySelectorAll('[data-act="run"]').forEach((btn) => {
    btn.addEventListener("click", () => runScheduleNow(parseInt(btn.dataset.id, 10)));
  });
  schedEls.list.querySelectorAll('[data-act="toggle"]').forEach((cb) => {
    cb.addEventListener("change", () =>
      toggleScheduleEnabled(parseInt(cb.dataset.id, 10), cb.checked),
    );
  });
  schedEls.list.querySelectorAll('[data-act="delete"]').forEach((btn) => {
    btn.addEventListener("click", () => deleteScheduleAction(parseInt(btn.dataset.id, 10)));
  });
}

async function runScheduleNow(id) {
  const sched = schedules.find((s) => s.id === id);
  const name = sched?.name || `schedule ${id}`;
  try {
    setStatus(`Running ${name}…`);
    await fetchJson(`/api/schedules/${id}/run-now`, { method: "POST" });
    setStatus(`Schedule "${name}" finished.`);
    await Promise.all([loadSchedules(), loadHistory()]);
  } catch (e) {
    setStatus(e.message, true);
    await loadSchedules();
  }
}

async function toggleScheduleEnabled(id, enabled) {
  try {
    await fetchJson(`/api/schedules/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    await loadSchedules();
  } catch (e) {
    setStatus(e.message, true);
    await loadSchedules();
  }
}

async function deleteScheduleAction(id) {
  const sched = schedules.find((s) => s.id === id);
  const name = sched?.name || `schedule ${id}`;
  const ok = await confirmModal({
    title: "Delete schedule",
    message: `"${name}" will stop running. Existing scans it produced are kept in History.`,
    confirmText: "Delete",
    danger: true,
  });
  if (!ok) return;
  try {
    await fetchJson(`/api/schedules/${id}`, { method: "DELETE" });
    await loadSchedules();
  } catch (e) {
    setStatus(e.message, true);
  }
}

function openScheduleModal() {
  schedEls.inputName.value = "";
  schedEls.inputCidr.value = els.cidr?.value?.trim() || "";
  schedEls.inputCron.value = "";
  schedEls.inputCron.hidden = true;
  schedEls.cronPresets.forEach((b, i) => b.classList.toggle("active", i === 0));
  schedEls.cronHint.innerHTML = "Runs every 15 minutes (<code>*/15 * * * *</code>).";
  schedEls.modalError.hidden = true;
  schedEls.modalError.textContent = "";
  schedEls.modal.hidden = false;
  setTimeout(() => schedEls.inputName.focus(), 0);
}

function closeScheduleModal() {
  schedEls.modal.hidden = true;
}

function selectedCronExpr() {
  const active = document.querySelector(".cron-preset.active");
  if (!active) return "*/15 * * * *";
  const c = active.dataset.cron;
  return c === "custom" ? schedEls.inputCron.value.trim() : c;
}

function showSchedError(msg) {
  schedEls.modalError.textContent = msg;
  schedEls.modalError.hidden = false;
}

async function submitScheduleModal() {
  const name = schedEls.inputName.value.trim();
  const cidr = schedEls.inputCidr.value.trim();
  const cronExpr = selectedCronExpr();
  if (!name) return showSchedError("Name is required.");
  if (!cidr) return showSchedError("CIDR is required.");
  if (!cronExpr) return showSchedError("Cron expression is required.");
  try {
    schedEls.modalCreate.disabled = true;
    await fetchJson("/api/schedules", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, cidr, cron_expr: cronExpr, enabled: true }),
    });
    closeScheduleModal();
    await loadSchedules();
  } catch (e) {
    showSchedError(e.message);
  } finally {
    schedEls.modalCreate.disabled = false;
  }
}

schedEls.newBtn?.addEventListener("click", openScheduleModal);
schedEls.refreshBtn?.addEventListener("click", loadSchedules);
schedEls.modalCreate?.addEventListener("click", submitScheduleModal);

schedEls.modalForm?.addEventListener("submit", (e) => {
  e.preventDefault();
  submitScheduleModal();
});

schedEls.modal?.querySelectorAll("[data-modal-close]").forEach((el) => {
  el.addEventListener("click", closeScheduleModal);
});

schedEls.cronPresets.forEach((btn) => {
  btn.addEventListener("click", () => {
    schedEls.cronPresets.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const c = btn.dataset.cron;
    if (c === "custom") {
      schedEls.inputCron.hidden = false;
      schedEls.cronHint.textContent = "Cron format: m h dom mon dow (e.g. 30 9 * * 1-5).";
      setTimeout(() => schedEls.inputCron.focus(), 0);
    } else {
      schedEls.inputCron.hidden = true;
      schedEls.cronHint.innerHTML = `${escapeHtml(cronHumanLabel(c))} (<code>${escapeHtml(c)}</code>).`;
    }
  });
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && schedEls.modal && !schedEls.modal.hidden) {
    e.preventDefault();
    closeScheduleModal();
  }
});

// v0.11.0 — notification channels UI

const chanEls = {
  list: document.getElementById("channel-list"),
  newBtn: document.getElementById("new-channel-btn"),
  refreshBtn: document.getElementById("refresh-channels"),
  modal: document.getElementById("modal-channel"),
  modalForm: document.getElementById("chan-modal-form"),
  modalError: document.getElementById("chan-modal-error"),
  modalCreate: document.getElementById("chan-modal-create"),
  inputName: document.getElementById("chan-name"),
  typePresets: Array.from(document.querySelectorAll("[data-chan-type]")),
  webhookFields: document.getElementById("chan-webhook-fields"),
  ntfyFields: document.getElementById("chan-ntfy-fields"),
  inputUrl: document.getElementById("chan-url"),
  formatPresets: Array.from(document.querySelectorAll("[data-chan-format]")),
  inputTopic: document.getElementById("chan-topic"),
  inputServer: document.getElementById("chan-server"),
  evtDone: document.getElementById("chan-evt-done"),
  evtError: document.getElementById("chan-evt-error"),
  evtSkipped: document.getElementById("chan-evt-skipped"),
  evtBaseline: document.getElementById("chan-evt-baseline"),
};

let channels = [];

async function loadChannels() {
  try {
    const { channels: rows } = await fetchJson("/api/notifications");
    channels = rows || [];
    renderChannels();
  } catch (e) {
    console.error("loadChannels failed:", e);
  }
}

function channelLastSentSummary(c) {
  if (!c.last_sent_at) return `<span class="channel-lastsent muted">Never sent</span>`;
  const ts = fmtClock(c.last_sent_at);
  if (c.last_status === "done") {
    return `<span class="channel-lastsent done" title="Last successful dispatch">✓ ${ts}</span>`;
  }
  if (c.last_status === "error") {
    const tip = c.last_error || "Error";
    return `<span class="channel-lastsent error" title="${escapeHtml(tip)}">✗ ${ts} · error</span>`;
  }
  return `<span class="channel-lastsent">${ts}</span>`;
}

function channelMetaLine(c) {
  if (c.type === "webhook") {
    const fmt = c.config?.format || "generic";
    return `<span class="channel-type-chip">webhook</span><code>${escapeHtml(fmt)}</code>`;
  }
  if (c.type === "ntfy") {
    const topic = c.config?.topic || "?";
    return `<span class="channel-type-chip">ntfy</span><code>${escapeHtml(topic)}</code>`;
  }
  return `<span class="channel-type-chip">${escapeHtml(c.type)}</span>`;
}

function renderChannelRow(c) {
  const checkedAttr = c.enabled ? "checked" : "";
  const events = (c.events || []).map((e) => e.replace("scan_", "")).join(", ");
  return `
    <li class="${c.enabled ? "" : "disabled"}" data-id="${c.id}">
      <span class="channel-name">${escapeHtml(c.name)}</span>
      <span class="channel-meta">${channelMetaLine(c)} · ${escapeHtml(events)}</span>
      ${channelLastSentSummary(c)}
      <div class="channel-controls">
        <button class="ghost small chan-test" data-act="test" data-id="${c.id}" title="Send a test payload now">▶ Test</button>
        <label class="chan-toggle" title="Enable or disable this channel">
          <input type="checkbox" data-act="toggle" data-id="${c.id}" ${checkedAttr} />
          <span>${c.enabled ? "On" : "Off"}</span>
        </label>
        <button class="chan-delete" data-act="delete" data-id="${c.id}" title="Delete channel" aria-label="Delete channel">×</button>
      </div>
    </li>`;
}

function renderChannels() {
  if (!channels.length) {
    chanEls.list.innerHTML = `<li class="muted">No channels yet.</li>`;
    return;
  }
  chanEls.list.innerHTML = channels.map(renderChannelRow).join("");
  chanEls.list.querySelectorAll('[data-act="test"]').forEach((btn) => {
    btn.addEventListener("click", () => testChannelNow(parseInt(btn.dataset.id, 10)));
  });
  chanEls.list.querySelectorAll('[data-act="toggle"]').forEach((cb) => {
    cb.addEventListener("change", () =>
      toggleChannelEnabled(parseInt(cb.dataset.id, 10), cb.checked),
    );
  });
  chanEls.list.querySelectorAll('[data-act="delete"]').forEach((btn) => {
    btn.addEventListener("click", () => deleteChannelAction(parseInt(btn.dataset.id, 10)));
  });
}

async function testChannelNow(id) {
  const ch = channels.find((c) => c.id === id);
  const name = ch?.name || `channel ${id}`;
  try {
    setStatus(`Testing ${name}…`);
    await fetchJson(`/api/notifications/${id}/test`, { method: "POST" });
    setStatus(`Test sent to ${name}.`);
    await loadChannels();
  } catch (e) {
    setStatus(`Test to ${name} failed: ${e.message}`, true);
    await loadChannels();
  }
}

async function toggleChannelEnabled(id, enabled) {
  try {
    await fetchJson(`/api/notifications/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    await loadChannels();
  } catch (e) {
    setStatus(e.message, true);
    await loadChannels();
  }
}

async function deleteChannelAction(id) {
  const ch = channels.find((c) => c.id === id);
  const name = ch?.name || `channel ${id}`;
  const ok = await confirmModal({
    title: "Delete channel",
    message: `"${name}" will stop receiving notifications. Past delivery history is also removed.`,
    confirmText: "Delete",
    danger: true,
  });
  if (!ok) return;
  try {
    await fetchJson(`/api/notifications/${id}`, { method: "DELETE" });
    await loadChannels();
  } catch (e) {
    setStatus(e.message, true);
  }
}

function selectedChannelType() {
  const active = document.querySelector(".cron-preset.active[data-chan-type]");
  return active?.dataset.chanType || "webhook";
}

function selectedWebhookFormat() {
  const active = document.querySelector(".cron-preset.active[data-chan-format]");
  return active?.dataset.chanFormat || "generic";
}

function selectedChannelEvents() {
  const out = [];
  if (chanEls.evtDone?.checked) out.push("scan_done");
  if (chanEls.evtError?.checked) out.push("scan_error");
  if (chanEls.evtSkipped?.checked) out.push("scan_skipped");
  if (chanEls.evtBaseline?.checked) out.push("baseline_diff");
  return out;
}

function syncChannelTypeUI() {
  const type = selectedChannelType();
  chanEls.webhookFields.hidden = type !== "webhook";
  chanEls.ntfyFields.hidden = type !== "ntfy";
}

function openChannelModal() {
  chanEls.inputName.value = "";
  chanEls.inputUrl.value = "";
  chanEls.inputTopic.value = "";
  chanEls.inputServer.value = "";
  chanEls.evtDone.checked = true;
  chanEls.evtError.checked = true;
  chanEls.evtSkipped.checked = false;
  chanEls.evtBaseline.checked = false;
  chanEls.typePresets.forEach((b, i) => b.classList.toggle("active", i === 0));
  chanEls.formatPresets.forEach((b, i) => b.classList.toggle("active", i === 0));
  syncChannelTypeUI();
  chanEls.modalError.hidden = true;
  chanEls.modalError.textContent = "";
  chanEls.modal.hidden = false;
  setTimeout(() => chanEls.inputName.focus(), 0);
}

function closeChannelModal() {
  chanEls.modal.hidden = true;
}

function showChanError(msg) {
  chanEls.modalError.textContent = msg;
  chanEls.modalError.hidden = false;
}

async function submitChannelModal() {
  const name = chanEls.inputName.value.trim();
  const type = selectedChannelType();
  const events = selectedChannelEvents();
  if (!name) return showChanError("Name is required.");
  if (events.length === 0) return showChanError("Select at least one event.");

  let config;
  if (type === "webhook") {
    const url = chanEls.inputUrl.value.trim();
    if (!url) return showChanError("Webhook URL is required.");
    config = { url, format: selectedWebhookFormat() };
  } else if (type === "ntfy") {
    const topic = chanEls.inputTopic.value.trim();
    if (!topic) return showChanError("Topic is required.");
    config = { topic };
    const server = chanEls.inputServer.value.trim();
    if (server) config.server = server;
  } else {
    return showChanError("Unknown channel type.");
  }

  try {
    chanEls.modalCreate.disabled = true;
    await fetchJson("/api/notifications", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, type, config, events, enabled: true }),
    });
    closeChannelModal();
    await loadChannels();
  } catch (e) {
    showChanError(e.message);
  } finally {
    chanEls.modalCreate.disabled = false;
  }
}

chanEls.newBtn?.addEventListener("click", openChannelModal);
chanEls.refreshBtn?.addEventListener("click", loadChannels);
chanEls.modalCreate?.addEventListener("click", submitChannelModal);

chanEls.modalForm?.addEventListener("submit", (e) => {
  e.preventDefault();
  submitChannelModal();
});

chanEls.modal?.querySelectorAll("[data-modal-close]").forEach((el) => {
  el.addEventListener("click", closeChannelModal);
});

chanEls.typePresets.forEach((btn) => {
  btn.addEventListener("click", () => {
    chanEls.typePresets.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    syncChannelTypeUI();
  });
});

chanEls.formatPresets.forEach((btn) => {
  btn.addEventListener("click", () => {
    chanEls.formatPresets.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
  });
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && chanEls.modal && !chanEls.modal.hidden) {
    e.preventDefault();
    closeChannelModal();
  }
});

loadBaselines();
loadHistory();
loadSchedules();
loadChannels();

// Demo mode (v0.9.0): the server tells us whether this is a read-only demo
// deploy. If so, expose the warning banner and disable controls that would
// otherwise produce 403s when the user tries them.
(async () => {
  try {
    const cfg = await fetchJson("/api/config");
    if (cfg.demoMode) {
      if (els.demoBanner) els.demoBanner.hidden = false;
      document.body.classList.add("demo-mode");
    }
  } catch (e) {
    console.warn("config fetch failed:", e);
  }
})();

// ===== Timeline (v0.12.0) =====
// Per-CIDR view aggregating all scans into 4 charts:
// hosts alive, open ports, scan duration and baseline diff.
const tlEls = {
  wrap: $("#results-timeline"),
  title: $("#timeline-title"),
  meta: $("#timeline-meta"),
  empty: $("#timeline-empty"),
  grid: $("#timeline-grid"),
  rangeWrap: $("#timeline-range"),
  closeBtn: $("#timeline-close"),
  noBaseline: $("#timeline-no-baseline"),
  canvas: {
    hosts: $("#chart-hosts"),
    ports: $("#chart-ports"),
    duration: $("#chart-duration"),
    diff: $("#chart-diff"),
  },
};

const tlState = { active: false, cidr: null, range: "all", charts: {} };

function setupTimeline() {
  if (!els.timelineBtn || !tlEls.wrap) return;
  els.timelineBtn.addEventListener("click", () => {
    if (lastScan) openTimeline(lastScan.cidr);
  });
  tlEls.closeBtn?.addEventListener("click", closeTimeline);
  tlEls.rangeWrap?.addEventListener("click", (e) => {
    const btn = e.target.closest(".range-btn");
    if (!btn) return;
    const range = btn.dataset.range;
    if (range === tlState.range) return;
    tlState.range = range;
    tlEls.rangeWrap.querySelectorAll(".range-btn").forEach((b) => {
      const on = b.dataset.range === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    refreshTimeline();
  });
  document.addEventListener("keydown", (e) => {
    if (tlState.active && e.key === "Escape") closeTimeline();
  });
}

async function openTimeline(cidr) {
  tlState.active = true;
  tlState.cidr = cidr;
  els.table.hidden = true;
  els.graphWrap.hidden = true;
  els.empty.hidden = true;
  const diffBanner = $("#diff-banner");
  if (diffBanner) diffBanner.hidden = true;
  tlEls.wrap.hidden = false;
  tlEls.title.textContent = `Timeline · ${cidr}`;
  tlEls.meta.textContent = "Loading…";
  await refreshTimeline();
}

function closeTimeline({ silent = false } = {}) {
  tlState.active = false;
  tlEls.wrap.hidden = true;
  destroyTimelineCharts();
  if (!silent && lastScan) renderScan(lastScan);
}

async function refreshTimeline() {
  if (!tlState.active || !tlState.cidr) return;
  try {
    const params = new URLSearchParams({ cidr: tlState.cidr, range: tlState.range });
    const data = await fetchJson(`/api/timeline?${params}`);
    renderTimelineCharts(data);
  } catch (e) {
    tlEls.meta.textContent = `Error: ${e.message}`;
    tlEls.empty.hidden = false;
    tlEls.empty.textContent = `Could not load timeline: ${e.message}`;
    tlEls.grid.hidden = true;
  }
}

function destroyTimelineCharts() {
  Object.values(tlState.charts).forEach((c) => c?.destroy?.());
  tlState.charts = {};
}

function readPaletteForCharts() {
  const cs = getComputedStyle(document.documentElement);
  return {
    accent: cs.getPropertyValue("--accent").trim() || "#22c55e",
    text: cs.getPropertyValue("--text").trim() || "#cbd5e1",
    muted: cs.getPropertyValue("--text-mute").trim() || "#94a3b8",
    border: cs.getPropertyValue("--border").trim() || "#222",
  };
}

function tlClickHandler(scanIds) {
  return (_evt, elements) => {
    if (!elements.length) return;
    const idx = elements[0].index;
    const id = scanIds[idx];
    if (!id) return;
    closeTimeline({ silent: true });
    loadScan(id);
  };
}

function renderTimelineCharts(data) {
  destroyTimelineCharts();
  const points = data.points || [];
  const hasBaseline = !!data.baseline;
  tlEls.meta.textContent =
    `${points.length} scan${points.length === 1 ? "" : "s"} · ` +
    (hasBaseline ? "baseline declared" : "no baseline");

  if (!points.length) {
    tlEls.grid.hidden = true;
    tlEls.empty.hidden = false;
    tlEls.empty.textContent = "No scans for this CIDR in the selected range.";
    return;
  }
  tlEls.empty.hidden = true;
  tlEls.grid.hidden = false;

  const labels = points.map((p) => {
    const d = new Date(p.started_at);
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  });
  const scanIds = points.map((p) => p.id);
  const palette = readPaletteForCharts();
  const onClick = tlClickHandler(scanIds);

  const baseOpts = (yLabel) => ({
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    onClick,
    scales: {
      x: { ticks: { color: palette.muted, maxRotation: 0, autoSkip: true }, grid: { color: palette.border } },
      y: { beginAtZero: true, ticks: { color: palette.muted }, grid: { color: palette.border }, title: { display: !!yLabel, text: yLabel, color: palette.muted } },
    },
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { title: (items) => items[0]?.label } },
    },
  });

  // Hosts alive
  tlState.charts.hosts = new Chart(tlEls.canvas.hosts, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Hosts alive",
        data: points.map((p) => p.host_count),
        borderColor: palette.accent,
        backgroundColor: palette.accent + "33",
        tension: 0.2,
        pointRadius: 4,
        pointHoverRadius: 6,
        fill: true,
      }],
    },
    options: baseOpts("hosts"),
  });

  // Open ports
  tlState.charts.ports = new Chart(tlEls.canvas.ports, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Open ports",
        data: points.map((p) => p.port_count),
        borderColor: "#3b82f6",
        backgroundColor: "#3b82f633",
        tension: 0.2,
        pointRadius: 4,
        pointHoverRadius: 6,
        fill: true,
      }],
    },
    options: baseOpts("ports"),
  });

  // Duration (seconds)
  tlState.charts.duration = new Chart(tlEls.canvas.duration, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Duration (s)",
        data: points.map((p) => (p.duration_ms != null ? Math.round(p.duration_ms / 1000) : 0)),
        backgroundColor: "#a78bfa",
        borderColor: "#7c3aed",
        borderWidth: 1,
      }],
    },
    options: baseOpts("seconds"),
  });

  // Baseline diff (appeared / disappeared)
  if (hasBaseline) {
    tlEls.noBaseline.hidden = true;
    tlState.charts.diff = new Chart(tlEls.canvas.diff, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Appeared",
            data: points.map((p) => p.diff?.appeared ?? null),
            borderColor: "#22c55e",
            backgroundColor: "#22c55e22",
            tension: 0.2,
            pointRadius: 4,
          },
          {
            label: "Disappeared",
            data: points.map((p) => p.diff?.disappeared ?? null),
            borderColor: "#ef4444",
            backgroundColor: "#ef444422",
            tension: 0.2,
            pointRadius: 4,
          },
        ],
      },
      options: {
        ...baseOpts("vs baseline"),
        plugins: { legend: { display: true, labels: { color: palette.text } } },
      },
    });
  } else {
    tlEls.noBaseline.hidden = false;
    tlEls.canvas.diff.style.display = "none";
  }
  // Reset display in case it was hidden before
  if (hasBaseline) tlEls.canvas.diff.style.display = "";
}

setupTimeline();

// ===== Alerts (v0.13.0) =====
// Sidebar entry opens a modal that lists baseline-divergence alerts. The
// badge is the canonical unack count and is refreshed at boot, after every
// scan / ack / delete / clear-history, and on a 30s timer to catch scheduled
// scans that fire while the tab is open. List filtering is purely additive:
// scope (unacked/all) is a single toggle, types are independent checkboxes.

const ALERT_TYPE_LABELS = {
  appeared: "appeared",
  disappeared: "disappeared",
  changed_mac: "changed mac",
  changed_hostname: "changed hostname",
  changed_os: "changed os",
  changed_ports: "changed ports",
};

const alertsEls = {
  badge: $("#alerts-badge"),
  openBtn: $("#open-alerts-btn"),
  modal: $("#modal-alerts"),
  list: $("#alerts-list"),
  scopeBtns: document.querySelectorAll("#modal-alerts [data-alert-scope]"),
  typeChecks: document.querySelectorAll("#modal-alerts .alerts-type-filters input[type=checkbox]"),
};

const alertsState = {
  scope: "unacked",
  types: new Set(),
};

let alertCountTimer = null;

function fmtAlertDetail(alert) {
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
    default:
      return ip;
  }
}

function formatAlertTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleString();
}

async function refreshAlertBadge() {
  // loadHistory() fires this on its boot pass before this module's const
  // initializers run; typeof avoids a TDZ ReferenceError.
  if (typeof alertsEls === "undefined" || !alertsEls?.badge) return;
  try {
    const res = await fetchJson("/api/alerts/count");
    const n = res?.count ?? 0;
    if (n > 0) {
      alertsEls.badge.hidden = false;
      alertsEls.badge.textContent = n > 99 ? "99+" : String(n);
    } else {
      alertsEls.badge.hidden = true;
    }
  } catch (e) {
    console.error("refreshAlertBadge failed:", e);
  }
}

async function loadAlerts() {
  if (!alertsEls.list) return;
  alertsEls.list.innerHTML = `<li class="muted">Loading…</li>`;
  const params = new URLSearchParams();
  if (alertsState.scope === "unacked") params.set("unackOnly", "true");
  if (alertsState.types.size > 0) params.set("types", [...alertsState.types].join(","));
  params.set("limit", "500");
  try {
    const res = await fetchJson(`/api/alerts?${params.toString()}`);
    renderAlerts(res.alerts || []);
  } catch (e) {
    alertsEls.list.innerHTML = `<li class="muted">Error: ${escapeHtml(e.message)}</li>`;
  }
}

function renderAlerts(alerts) {
  if (!alerts.length) {
    const scopeMsg = alertsState.scope === "unacked"
      ? "No unacknowledged alerts."
      : "No alerts match the current filter.";
    alertsEls.list.innerHTML = `<li class="muted">${scopeMsg}</li>`;
    return;
  }
  alertsEls.list.innerHTML = alerts.map(renderAlertRow).join("");
  alertsEls.list.querySelectorAll('[data-act="ack"]').forEach((btn) => {
    btn.addEventListener("click", () => ackAlertHandler(parseInt(btn.dataset.id, 10)));
  });
  alertsEls.list.querySelectorAll('[data-act="delete"]').forEach((btn) => {
    btn.addEventListener("click", () => deleteAlertHandler(parseInt(btn.dataset.id, 10)));
  });
  alertsEls.list.querySelectorAll('[data-act="scan"]').forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = parseInt(btn.dataset.scanId, 10);
      closeAlertsModal();
      loadScan(id);
    });
  });
}

function renderAlertRow(a) {
  const acked = a.acknowledged_at != null;
  const detail = fmtAlertDetail(a);
  const created = formatAlertTime(a.created_at);
  const typeLabel = ALERT_TYPE_LABELS[a.type] || a.type;
  return `
    <li class="alert-row${acked ? " acked" : ""}" data-id="${a.id}">
      <span class="alert-type-chip ${a.type}">${escapeHtml(typeLabel)}</span>
      <span class="alert-detail">${escapeHtml(detail)}</span>
      <span class="alert-meta">
        <button class="ghost small" data-act="scan" data-scan-id="${a.scan_id}" title="Open scan #${a.scan_id}">scan #${a.scan_id}</button>
        <span>· ${escapeHtml(created)}</span>
        ${acked ? `<span class="alert-ack-label">· ✓ acked</span>` : ""}
      </span>
      <span class="alert-actions">
        ${acked ? "" : `<button class="ghost small" data-act="ack" data-id="${a.id}" title="Acknowledge">✓ Ack</button>`}
        <button class="alert-delete" data-act="delete" data-id="${a.id}" title="Delete alert">×</button>
      </span>
    </li>
  `;
}

async function ackAlertHandler(id) {
  try {
    await fetchJson(`/api/alerts/${id}/ack`, { method: "POST" });
    await Promise.all([loadAlerts(), refreshAlertBadge()]);
  } catch (e) {
    console.error("ack failed:", e);
  }
}

async function deleteAlertHandler(id) {
  try {
    await fetchJson(`/api/alerts/${id}`, { method: "DELETE" });
    await Promise.all([loadAlerts(), refreshAlertBadge()]);
  } catch (e) {
    console.error("delete failed:", e);
  }
}

function openAlertsModal() {
  if (!alertsEls.modal) return;
  alertsEls.modal.hidden = false;
  loadAlerts();
}

function closeAlertsModal() {
  if (!alertsEls.modal) return;
  alertsEls.modal.hidden = true;
}

function setupAlerts() {
  if (!alertsEls.openBtn) return;
  alertsEls.openBtn.addEventListener("click", openAlertsModal);
  alertsEls.modal?.querySelectorAll("[data-modal-close]").forEach((el) => {
    el.addEventListener("click", closeAlertsModal);
  });
  alertsEls.scopeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      alertsEls.scopeBtns.forEach((b) => b.classList.toggle("active", b === btn));
      alertsState.scope = btn.dataset.alertScope;
      loadAlerts();
    });
  });
  alertsEls.typeChecks.forEach((cb) => {
    cb.addEventListener("change", () => {
      if (cb.checked) alertsState.types.add(cb.value);
      else alertsState.types.delete(cb.value);
      loadAlerts();
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && alertsEls.modal && !alertsEls.modal.hidden) {
      e.preventDefault();
      closeAlertsModal();
    }
  });
  refreshAlertBadge();
  if (alertCountTimer) clearInterval(alertCountTimer);
  alertCountTimer = setInterval(refreshAlertBadge, 30000);
}

setupAlerts();
