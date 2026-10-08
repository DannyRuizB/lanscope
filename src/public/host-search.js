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
//
// v1.46.0 — field keywords and quoted phrases. Measured on the demo seed, a
// bare IP is the worst substring of all: `192.168.1.1` matches SEVEN hosts
// (.1, .10, .11, .12, .100, .101, .150) and `192.168.1.10` three. So
// `ip:192.168.1.1` is exact, and `ip:192.168.1.0/28` a CIDR block (IPv4,
// like the scanner). `mac:` is a prefix - an OUI, any of `:`, `-` or no
// separator. `vendor:`, `os:` and `name:` (hostname or label) are a
// substring of THAT field only - on the seed, `pi` hits pihole AND
// homeassistant (a Raspberry Pi), `name:pi` only pihole; `apple` hits the Mac
// and the iPhone, `os:apple` only the host nmap fingerprinted as macOS.
// A double-quoted phrase keeps its spaces, alone or as a
// keyword value: `"apple, inc."`, `vendor:"raspberry pi"`; an unterminated
// quote runs to the end of the query.
//
// v1.47.0 — `is:new` and `is:changed`, against the ACTIVE comparison (the
// base scan the diff view is showing: a manual Compare, or the CIDR's
// baseline). `is:new` is a host that appeared since the base, `is:changed`
// one whose ports / OS / vendor / MAC moved - the same classification the
// diff colours rows by (scan-diff.js), so the filter and the colours cannot
// disagree. With no comparison active there is nothing to be new AGAINST:
// both match nothing, and `needsComparison()` lets the UI say why instead of
// showing a silently empty table.
//
// v1.48.0 — `is:gone`: a host that was in the base scan and is not in this
// one - the "Disappeared since base scan" rows, which the search now filters
// too (before, every query left them all on screen).
//
// v1.49.0 — `port:`, `tcp:` and `udp:` take ranges and lists: `port:8000-8999`
// (an open port anywhere in the range, ends included), `port:22,80,443` (any
// of them), or both mixed (`tcp:22,8000-8100`). Same rule as before for what
// cannot be used: a reversed range (`8100-8000`), a port outside 1-65535 or
// an empty item (`22,,80`) matches NOTHING. Negation reads as "no open port
// in it": `-tcp:1-1023` is the hosts with nothing open below 1024.
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
    new: (host, label, diff) => diff === "appeared",
    changed: (host, label, diff) => diff === "changed",
    gone: (host, label, diff) => diff === "disappeared",
  };
  const DIFF_KEYWORDS = new Set(["is:new", "is:changed", "is:gone"]);

  function openIn(list, ranges) {
    return (list || []).some((p) => p.state === "open" && ranges.some(([lo, hi]) => Number(p.port) >= lo && Number(p.port) <= hi));
  }

  // A whole number 1-65535, or null.
  function portNumber(v) {
    if (!/^\d{1,5}$/.test(v)) return null;
    const n = Number(v);
    return n >= 1 && n <= 65535 ? n : null;
  }

  // A port keyword's value - `22`, `8000-8999`, `22,80,443-445` - as a list
  // of [lo, hi] ranges, or null if any part of it is unusable.
  function portRanges(v) {
    const out = [];
    for (const item of v.split(",")) {
      const m = /^(\d+)(?:-(\d+))?$/.exec(item);
      if (!m) return null;
      const lo = portNumber(m[1]);
      const hi = m[2] === undefined ? lo : portNumber(m[2]);
      if (lo === null || hi === null || hi < lo) return null;
      out.push([lo, hi]);
    }
    return out;
  }

  // A dotted-quad IPv4 as an unsigned 32-bit number, or null.
  function ipv4(v) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    if (!m) return null;
    const o = m.slice(1).map(Number);
    if (o.some((x) => x > 255)) return null;
    return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  }

  // `ip:` value: an exact address, or a CIDR block a.b.c.d/n (0-32).
  function ipMatches(ip, v) {
    const [addr, bits, extra] = v.split("/");
    if (extra !== undefined) return false;
    const want = ipv4(addr);
    const have = ipv4(String(ip || ""));
    if (want === null || have === null) return false;
    if (bits === undefined) return want === have;
    if (!/^\d{1,2}$/.test(bits) || Number(bits) > 32) return false;
    const mask = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
    return ((want & mask) >>> 0) === ((have & mask) >>> 0);
  }

  // v1.52.0 — a numeric comparison: `>50`, `>=50`, `<5`, `<=5`, `50` (equal)
  // or `10-50` (inclusive), decimals allowed. A predicate, or null when the
  // value is unusable (so the keyword matches nothing, like a bad port).
  function comparison(v) {
    const num = "(\\d+(?:\\.\\d+)?)";
    let m = new RegExp(`^(>=|<=|>|<|=)?${num}$`).exec(v);
    if (m) {
      const n = Number(m[2]);
      const op = m[1] || "=";
      return (x) => (op === ">" ? x > n : op === ">=" ? x >= n : op === "<" ? x < n : op === "<=" ? x <= n : x === n);
    }
    m = new RegExp(`^${num}-${num}$`).exec(v);
    if (m && Number(m[1]) <= Number(m[2])) {
      const lo = Number(m[1]);
      const hi = Number(m[2]);
      return (x) => x >= lo && x <= hi;
    }
    return null;
  }

  // The number the Ports column shows (open TCP), or null when it is not
  // known: never port-scanned, or the scan hit the per-host timeout (a
  // partial list - "0 open" there is not a fact).
  function openTcpCount(host) {
    if (!host.portscanned_at || host.port_timedout) return null;
    return (host.ports || []).filter((p) => p.state === "open").length;
  }

  // A measured value against a comparison; an unknown value never matches.
  function compares(value, v) {
    const test = comparison(v);
    return test !== null && value !== null && value !== undefined && Number.isFinite(Number(value)) && test(Number(value));
  }

  const hex = (v) => String(v || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  const has = (field, v) => v !== "" && String(field || "").toLowerCase().includes(v);

  const KEYWORDS = {
    ip: (host, v) => ipMatches(host.ip, v),
    mac: (host, v) => /^[0-9a-f:-]+$/.test(v) && hex(v) !== "" && hex(host.mac).startsWith(hex(v)),
    vendor: (host, v) => has(host.vendor, v),
    os: (host, v) => (host.os_matches || []).some((m) => has(m.name, v)),
    name: (host, v, label) => has(host.hostname, v) || has(label, v),
    is: (host, v, label, diff) => (IS[v] ? IS[v](host, label, diff) : false),
    port: (host, v) => {
      const r = portRanges(v);
      return r !== null && (openIn(host.ports, r) || openIn(host.udp_ports, r));
    },
    tcp: (host, v) => {
      const r = portRanges(v);
      return r !== null && openIn(host.ports, r);
    },
    udp: (host, v) => {
      const r = portRanges(v);
      return r !== null && openIn(host.udp_ports, r);
    },
    ports: (host, v) => compares(openTcpCount(host), v),
    latency: (host, v) => compares(host.latency_ms, v),
  };

  function matchTerm(host, term, label, hay, diff) {
    const m = /^([a-z]+):(.*)$/.exec(term);
    if (m && KEYWORDS[m[1]]) return KEYWORDS[m[1]](host, m[2], label, diff);
    return hay().includes(term);
  }

  // True when the host matches the query. An empty / whitespace query
  // matches everything (no filter applied).
  // Split a query into terms: whitespace separates, a double-quoted run
  // (alone or after `keyword:` / `-`) keeps its spaces and loses its quotes.
  function tokenize(query) {
    const out = [];
    const re = /(-?(?:[a-z]+:)?)"([^"]*)"?|\S+/g;
    let m;
    while ((m = re.exec(query)) !== null) {
      if (m[2] !== undefined) out.push(m[1] + m[2]);
      else out.push(m[0]);
    }
    return out.filter((t) => t !== "");
  }

  // `diff` is the host's state in the active comparison ("appeared",
  // "changed", "unchanged") or null when no comparison is active.
  function matchHost(host, query, label, diff) {
    const terms = tokenize(String(query || "").trim().toLowerCase());
    if (!terms.length) return true;
    let cached = null;
    const hay = () => (cached === null ? (cached = haystack(host, label)) : cached);
    return terms.every((t) => {
      const negated = t.length > 1 && t.startsWith("-");
      const hit = matchTerm(host, negated ? t.slice(1) : t, label, hay, diff || null);
      return negated ? !hit : hit;
    });
  }

  // Filter a host list by the query. `labelFor` is an optional
  // (ip) => label|null lookup so the friendly name is searchable too, and
  // `diffFor` an optional (ip) => diff state|null for is:new / is:changed.
  function searchHosts(hosts, query, labelFor, diffFor) {
    const q = String(query || "").trim();
    if (!q) return hosts;
    const lookup = typeof labelFor === "function" ? labelFor : () => null;
    const diffOf = typeof diffFor === "function" ? diffFor : () => null;
    return hosts.filter((h) => matchHost(h, q, lookup(h.ip), diffOf(h.ip)));
  }

  // True when the query uses a keyword that only means something against a
  // comparison (negated or not), so the UI can explain an empty result.
  function needsComparison(query) {
    return tokenize(String(query || "").trim().toLowerCase())
      .some((t) => DIFF_KEYWORDS.has(t.startsWith("-") ? t.slice(1) : t));
  }

  const api = { matchHost, searchHosts, tokenize, needsComparison };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.HostSearch = api;
})(typeof window !== "undefined" ? window : globalThis);
