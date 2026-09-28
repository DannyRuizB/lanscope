// Host search (v1.11.0) — free-text filter over the results table.
//
// Pure and DOM-free so it can be unit-tested under node AND used in the
// browser: the dual export at the bottom puts it on `window.HostSearch`
// for app.js and on `module.exports` for `node --test`. Matching is a
// case-insensitive substring over everything a person would type looking
// for a device: IP, MAC, vendor, hostname, its friendly label, detected OS
// names and its open TCP/UDP port numbers. One keyword filter too:
// `is:timedout` lists the hosts whose port scan came back partial.
//
// v1.45.0 — the query is a list of TERMS separated by spaces, and a host must
// match EVERY one (AND); a leading `-` negates a term. Besides the substring,
// a term can be a keyword: `port:N` (an open TCP or UDP port, exact), `tcp:N`,
// `udp:N`, `is:up`, `is:down`, `is:labeled`, `is:timedout`. Exact matters: as
// a substring, `22` also hits 2222, 10.0.0.22 and every MAC with a :22: in
// it. A keyword with a value it cannot use (`port:ssh`, `is:nope`) matches
// NOTHING rather than falling back to the substring, so a typo shows up as an
// empty table instead of as a plausible-looking wrong one.
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

  // v1.44.0 — `is:timedout`: hosts whose TCP or UDP port scan hit the
  // per-host timeout (v1.41 records it). Their port list is a PARTIAL answer:
  // "0 open" there means "unknown", and this is how to list them all.
  const IS = {
    timedout: (host) => !!(host.port_timedout || host.udp_port_timedout),
    up: (host) => host.status === "up",
    down: (host) => host.status === "down",
    labeled: (host, label) => !!(label && String(label).trim()),
  };

  function openOn(list, port) {
    return (list || []).some((p) => Number(p.port) === port && p.state === "open");
  }

  // A port keyword's value: a whole number 1-65535, or null.
  function portValue(v) {
    if (!/^\d{1,5}$/.test(v)) return null;
    const n = Number(v);
    return n >= 1 && n <= 65535 ? n : null;
  }

  const KEYWORDS = {
    is: (host, v, label) => (IS[v] ? IS[v](host, label) : false),
    port: (host, v) => {
      const n = portValue(v);
      return n !== null && (openOn(host.ports, n) || openOn(host.udp_ports, n));
    },
    tcp: (host, v) => {
      const n = portValue(v);
      return n !== null && openOn(host.ports, n);
    },
    udp: (host, v) => {
      const n = portValue(v);
      return n !== null && openOn(host.udp_ports, n);
    },
  };

  function matchTerm(host, term, label, hay) {
    const m = /^([a-z]+):(.*)$/.exec(term);
    if (m && KEYWORDS[m[1]]) return KEYWORDS[m[1]](host, m[2], label);
    return hay().includes(term);
  }

  // True when the host matches the query. An empty / whitespace query
  // matches everything (no filter applied).
  function matchHost(host, query, label) {
    const terms = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return true;
    let cached = null;
    const hay = () => (cached === null ? (cached = haystack(host, label)) : cached);
    return terms.every((t) => {
      const negated = t.length > 1 && t.startsWith("-");
      const hit = matchTerm(host, negated ? t.slice(1) : t, label, hay);
      return negated ? !hit : hit;
    });
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
