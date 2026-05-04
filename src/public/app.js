const $ = (sel) => document.querySelector(sel);

const els = {
  form: $("#scan-form"),
  cidr: $("#cidr"),
  scanBtn: $("#scan-btn"),
  status: $("#scan-status"),
  refresh: $("#refresh-history"),
  list: $("#scan-list"),
  resultsHeader: $("#results-header"),
  resultsCidr: $("#results-cidr"),
  resultsMeta: $("#results-meta"),
  empty: $("#results-empty"),
  table: $("#results-table"),
  body: $("#results-body"),
  deleteBtn: $("#delete-scan"),
};

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

function renderHostRow(h) {
  return `
    <tr class="host-row" data-host-id="${h.id}">
      <td class="ip">${escapeHtml(h.ip)}</td>
      <td class="${h.mac ? "" : "muted"}">${escapeHtml(h.mac) || "—"}</td>
      <td class="${h.vendor ? "" : "muted"}">${escapeHtml(h.vendor) || "—"}</td>
      <td class="${h.hostname ? "" : "muted"}">${escapeHtml(h.hostname) || "—"}</td>
      <td class="muted">${escapeHtml(h.reason) || "—"}</td>
      <td class="ports-cell">${renderPortsButton(h)}</td>
    </tr>
    <tr class="host-detail" data-host-id="${h.id}" hidden>
      <td colspan="6">${h.ports?.length ? renderPortsTable(h) : ""}</td>
    </tr>`;
}

function renderPortsTable(host) {
  const ports = host.ports || [];
  if (!ports.length) {
    return `<div class="ports-empty">No open ports detected on top 100.</div>`;
  }
  const rows = ports
    .map(
      (p) => `
      <tr>
        <td class="port-num">${p.port}/${escapeHtml(p.protocol)}</td>
        <td><span class="state-pill state-${escapeHtml(p.state)}">${escapeHtml(p.state)}</span></td>
        <td class="${p.service ? "" : "muted"}">${escapeHtml(p.service) || "—"}</td>
        <td class="${p.product ? "" : "muted"}">${escapeHtml(p.product) || "—"}</td>
        <td class="${p.version ? "" : "muted"}">${escapeHtml(p.version) || "—"}</td>
      </tr>`,
    )
    .join("");
  return `
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
}

function attachPortscanHandlers() {
  els.body.querySelectorAll(".portscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => onPortscanClick(parseInt(btn.dataset.hostId, 10)));
  });
}

async function onPortscanClick(hostId) {
  const host = currentHostsById().get(hostId);
  if (!host) return;
  if (host.portscanned_at) {
    toggleHostDetail(hostId);
    return;
  }
  await runPortscan(hostId);
}

function currentHostsById() {
  // Walk visible rows and remember the host objects we last rendered.
  // We pull from the most recent `lastScan`.
  const m = new Map();
  if (lastScan?.hosts) for (const h of lastScan.hosts) m.set(h.id, h);
  return m;
}

let lastScan = null;

function toggleHostDetail(hostId) {
  const detail = els.body.querySelector(`tr.host-detail[data-host-id="${hostId}"]`);
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
    const data = await fetchJson(`/api/hosts/${hostId}/portscan`, { method: "POST" });
    // Patch lastScan in memory and re-render this row + detail.
    if (lastScan) {
      const h = lastScan.hosts.find((x) => x.id === hostId);
      if (h) {
        h.ports = data.ports;
        h.portscanned_at = data.portscanned_at;
      }
    }
    const detail = els.body.querySelector(`tr.host-detail[data-host-id="${hostId}"]`);
    if (detail) {
      const host = lastScan?.hosts.find((x) => x.id === hostId);
      detail.querySelector("td").innerHTML = host ? renderPortsTable(host) : "";
      detail.hidden = false;
    }
    btn.textContent = portsButtonLabel(lastScan.hosts.find((x) => x.id === hostId));
    btn.disabled = false;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = original;
    setStatus(`Port scan failed: ${e.message}`, true);
  }
}

async function runScan(cidr) {
  els.scanBtn.disabled = true;
  setStatus(`Scanning ${cidr}… this can take a few seconds.`);
  try {
    const scan = await fetchJson("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidr }),
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

els.refresh.addEventListener("click", loadHistory);

els.deleteBtn.addEventListener("click", async () => {
  if (!activeScanId) return;
  if (!confirm("Delete this scan?")) return;
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
