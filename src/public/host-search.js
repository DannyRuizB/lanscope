// Host search (v1.11.0) — free-text filter over the results table.
//
// Pure and DOM-free so it can be unit-tested under node AND used in the
// browser: the dual export at the bottom puts it on `window.HostSearch`
// for app.js and on `module.exports` for `node --test`. Matching is a
// case-insensitive substring over everything a person would type looking
// for a device: IP, MAC, vendor, hostname, its friendly label, detected OS
// names and its open TCP/UDP port numbers. One keyword filter too:
// `is:timedout` lists the hosts whose port scan came back partial.
(function (global) {
  "use strict";

  function haystack(host, label) {
    const parts = [
      host.ip,
      host.mac,
      host.vendor,
      host.hostname,
      label || "",
    ];
    for (const m of host.os_matches || []) parts.push(m.name);
    for (const p of host.ports || []) {
      if (p.state === "open") parts.push(String(p.port));
    }
    // v1.44.0: the UDP ports this comment always promised. Only the ones that
    // ANSWERED ("open"); "open|filtered" means nmap got no reply and cannot
    // tell - searching 161 must not surface a host whose 161 said nothing.
    for (const p of host.udp_ports || []) {
      if (p.state === "open") parts.push(String(p.port));
    }
    return parts.filter(Boolean).join(" ").toLowerCase();
  }

  // True when the host matches the query. An empty / whitespace query
  // matches everything (no filter applied).
  // v1.44.0 — `is:timedout`: hosts whose TCP or UDP port scan hit the
  // per-host timeout (v1.41 records it). Their port list is a PARTIAL answer:
  // "0 open" there means "unknown", and this is how to list them all.
  const FILTERS = {
    "is:timedout": (host) => !!(host.port_timedout || host.udp_port_timedout),
  };

  function matchHost(host, query, label) {
    const q = String(query || "").trim().toLowerCase();
    if (!q) return true;
    if (FILTERS[q]) return FILTERS[q](host);
    return haystack(host, label).includes(q);
  }

  // Filter a host list by the query. `labelFor` is an optional
  // (ip) => label|null lookup so the friendly name is searchable too.
  function searchHosts(hosts, query, labelFor) {
    const q = String(query || "").trim();
    if (!q) return hosts;
    const lookup = typeof labelFor === "function" ? labelFor : () => null;
    return hosts.filter((h) => matchHost(h, q, lookup(h.ip)));
  }

  const api = { matchHost, searchHosts };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.HostSearch = api;
})(typeof window !== "undefined" ? window : globalThis);
