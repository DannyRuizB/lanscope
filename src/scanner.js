const { execFile } = require("node:child_process");
const { XMLParser } = require("fast-xml-parser");

// CIDR validation: IPv4 a.b.c.d/n where n in [0,32]. Strict regex,
// no whitespace, no shell metacharacters reach nmap.
const CIDR_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(?:3[0-2]|[12]?\d)$/;

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function validateCidr(cidr) {
  if (typeof cidr !== "string") return "cidr must be a string";
  if (!CIDR_RE.test(cidr)) return "invalid CIDR (expected IPv4 a.b.c.d/n)";
  return null;
}

function validateIpv4(ip) {
  if (typeof ip !== "string") return "ip must be a string";
  if (!IPV4_RE.test(ip)) return "invalid IPv4 address";
  return null;
}

const TIMING_VALUES = new Set(["T0", "T1", "T2", "T3", "T4", "T5"]);

// timing is optional; null/undefined means "use scan default".
// Returns { value: "T4" | null, error: string | null }.
function validateTiming(t) {
  if (t === undefined || t === null || t === "") return { value: null, error: null };
  if (typeof t !== "string") return { value: null, error: "timing must be a string" };
  if (!TIMING_VALUES.has(t)) return { value: null, error: "timing must be one of T0..T5" };
  return { value: t, error: null };
}

const SCAN_TYPE_VALUES = new Set(["connect", "syn"]);

// scanType is optional; null/undefined means "use scan default" (connect).
// Returns { value: "connect" | "syn" | null, error: string | null }.
function validateScanType(t) {
  if (t === undefined || t === null || t === "") return { value: null, error: null };
  if (typeof t !== "string") return { value: null, error: "scanType must be a string" };
  if (!SCAN_TYPE_VALUES.has(t)) return { value: null, error: "scanType must be 'connect' or 'syn'" };
  return { value: t, error: null };
}

// NSE script categories we expose. Curated allowlist: "default" (the same set
// nmap runs with -sC, includes banner/http-title/ssh-hostkey…) and "safe"
// (broader but still classified by nmap as not intrusive). Categories like
// "vuln", "exploit", "brute", "intrusive", "dos" are NOT exposed — lanscope
// is a visibility tool, not a security scanner. Input is an array; backend
// validates each entry against this set, no free-form strings reach nmap.
const ALLOWED_SCRIPT_CATEGORIES = new Set(["default", "safe"]);

// scripts is optional; null/undefined/[] means "no NSE".
// Returns { args: ["--script=default,safe"] | [], error: string | null }.
function validateScripts(scripts) {
  if (scripts === undefined || scripts === null) return { args: [], error: null };
  if (!Array.isArray(scripts)) return { args: null, error: "scripts must be an array" };
  if (scripts.length === 0) return { args: [], error: null };
  const seen = new Set();
  for (const s of scripts) {
    if (typeof s !== "string" || !ALLOWED_SCRIPT_CATEGORIES.has(s)) {
      return { args: null, error: `script category not allowed: ${s}` };
    }
    seen.add(s);
  }
  return { args: [`--script=${[...seen].join(",")}`], error: null };
}

// Host discovery flags exposed in v0.6. Allowlist of nmap ping-type letters
// we route into args. -Pn (skip discovery) is mutually exclusive with the
// others: when set, nmap treats every host in the CIDR as up and the
// per-type pings are not used. Per-type values map 1:1 to nmap flags
// (-PE ICMP echo, -PS TCP SYN ping, -PA TCP ACK ping, -PR ARP).
const ALLOWED_PING_TYPES = new Set(["PE", "PS", "PA", "PR"]);

// discovery is optional; null/undefined/{} means "use nmap defaults".
// Returns { args: ["-Pn"] | ["-PE","-PS",…] | [], error: string | null }.
function validateDiscovery(discovery) {
  if (discovery === undefined || discovery === null) return { args: [], error: null };
  if (typeof discovery !== "object" || Array.isArray(discovery)) {
    return { args: null, error: "discovery must be an object" };
  }
  const { skipPing, pingTypes } = discovery;
  if (skipPing !== undefined && typeof skipPing !== "boolean") {
    return { args: null, error: "discovery.skipPing must be a boolean" };
  }
  if (skipPing === true) return { args: ["-Pn"], error: null };

  if (pingTypes === undefined || pingTypes === null) return { args: [], error: null };
  if (!Array.isArray(pingTypes)) return { args: null, error: "discovery.pingTypes must be an array" };
  if (pingTypes.length === 0) return { args: [], error: null };
  const seen = new Set();
  for (const t of pingTypes) {
    if (typeof t !== "string" || !ALLOWED_PING_TYPES.has(t)) {
      return { args: null, error: `ping type not allowed: ${t}` };
    }
    seen.add(t);
  }
  return { args: [...seen].map((t) => `-${t}`), error: null };
}

// Range spec: comma-separated list of `N` or `N-M`, no spaces, no other chars.
// Each port in [1,65535], N<=M, max 100 tokens to keep argv sane.
const RANGE_SPEC_RE = /^(\d+(-\d+)?)(,\d+(-\d+)?)*$/;
const PORTS_DEFAULT_ARGS = ["--top-ports", "100"];

// ports is optional; null/undefined means default top-100.
// Accepts { mode: "top", value: 1..65535 } or { mode: "range", value: "<spec>" }.
// Returns { args: ["--top-ports","N"] | ["-p","<spec>"], error: string | null }.
function validatePortsSpec(ports) {
  if (ports === undefined || ports === null) return { args: PORTS_DEFAULT_ARGS, error: null };
  if (typeof ports !== "object") return { args: null, error: "ports must be an object" };

  const { mode, value } = ports;
  if (mode === "top") {
    const n = typeof value === "number" ? value : parseInt(value, 10);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return { args: null, error: "top-N must be an integer 1..65535" };
    }
    return { args: ["--top-ports", String(n)], error: null };
  }

  if (mode === "range") {
    if (typeof value !== "string" || !RANGE_SPEC_RE.test(value)) {
      return { args: null, error: "range must be like 80, 1-1024, or 22,80,443,8000-8100" };
    }
    const tokens = value.split(",");
    if (tokens.length > 100) return { args: null, error: "range has too many tokens (max 100)" };
    for (const tok of tokens) {
      const [a, b] = tok.split("-").map((s) => parseInt(s, 10));
      const lo = a;
      const hi = b === undefined ? a : b;
      if (lo < 1 || hi > 65535 || lo > hi) {
        return { args: null, error: `invalid port token: ${tok}` };
      }
    }
    return { args: ["-p", value], error: null };
  }

  return { args: null, error: "ports.mode must be 'top' or 'range'" };
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  isArray: (name) =>
    name === "host" ||
    name === "address" ||
    name === "hostname" ||
    name === "port" ||
    name === "osmatch" ||
    name === "osclass" ||
    name === "script",
});

// Pulls every <script id="..." output="..."/> under a parent node.
// Used both for <port><script>…</script></port> (port-level) and
// <hostscript><script>…</script></hostscript> (host-level). nmap's XML
// nests detail tables inside, but for v0.5 we just keep the flat `output`
// attribute (already a human-readable summary) — structured tables can
// come later if a script's flat output is unusable.
function extractScripts(parent) {
  const list = parent?.script || [];
  return list
    .map((s) => ({
      script_id: s.id || "unknown",
      output: decodeXmlNumericEntities(typeof s.output === "string" ? s.output : ""),
    }))
    .filter((s) => s.script_id);
}

// nmap's XML escapes newlines/tabs inside script output attributes as
// numeric character references (&#xa; &#xd; &#9; …). fast-xml-parser only
// decodes the named entities by default, so we reverse the numeric ones
// here. Without this the UI would print literal "&#xa;" instead of newlines.
function decodeXmlNumericEntities(s) {
  if (typeof s !== "string") return s;
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
      const cp = parseInt(hex, 16);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : "";
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      const cp = parseInt(dec, 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : "";
    });
}

function pickAddress(addresses, type) {
  return addresses?.find((a) => a.addrtype === type);
}

function parseHosts(xml) {
  const doc = xmlParser.parse(xml);
  const hosts = doc?.nmaprun?.host || [];
  return hosts
    .map((h) => {
      const addresses = h.address || [];
      const ipv4 = pickAddress(addresses, "ipv4");
      const mac = pickAddress(addresses, "mac");
      const hostnames = h.hostnames?.hostname || [];
      return {
        ip: ipv4?.addr || null,
        mac: mac?.addr || null,
        vendor: mac?.vendor || null,
        hostname: hostnames[0]?.name || null,
        status: h.status?.state === "up" ? "up" : "down",
        reason: h.status?.reason || null,
      };
    })
    .filter((h) => h.ip);
}

function runPingSweep(cidr, opts = {}) {
  const discoveryArgs = opts.discoveryArgs || [];
  return new Promise((resolve, reject) => {
    // -sn: ping scan, no port scan
    // -n: no DNS resolution from nmap (we get rDNS via PTR if available; -n is faster)
    //     ...actually we DO want PTR for hostnames, so omit -n.
    // -oX -: XML output to stdout
    // -T4: faster timing
    // discoveryArgs (v0.6): optional, validated upstream. Either ["-Pn"]
    //   (treat all hosts up, skip discovery probes) or any combination of
    //   ["-PE","-PS","-PA","-PR"]. Empty array = nmap defaults.
    execFile(
      "nmap",
      ["-sn", "-T4", ...discoveryArgs, "-oX", "-", cidr],
      { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 },
      (err, stdout, stderr) => {
        if (err) {
          const msg = stderr?.toString().trim() || err.message;
          return reject(new Error(`nmap failed: ${msg}`));
        }
        try {
          resolve(parseHosts(stdout));
        } catch (e) {
          reject(new Error(`failed to parse nmap output: ${e.message}`));
        }
      },
    );
  });
}

function parsePorts(xml) {
  const doc = xmlParser.parse(xml);
  const hosts = doc?.nmaprun?.host || [];
  // We expect one host (we scanned one IP). Take the first.
  const host = hosts[0];
  if (!host) return [];
  const ports = host.ports?.port || [];
  return ports.map((p) => {
    const svc = p.service || {};
    const extra = [svc.extrainfo, svc.ostype, svc.cpe]
      .filter((x) => x && typeof x === "string")
      .join(" · ");
    return {
      port: parseInt(p.portid, 10),
      protocol: p.protocol || "tcp",
      state: p.state?.state || "unknown",
      state_reason: p.state?.reason || null,
      service: svc.name || null,
      product: svc.product || null,
      version: svc.version || null,
      extra: extra || null,
      scripts: extractScripts(p),
    };
  });
}

function parseHostScripts(xml) {
  const doc = xmlParser.parse(xml);
  const hosts = doc?.nmaprun?.host || [];
  const host = hosts[0];
  if (!host) return [];
  return extractScripts(host.hostscript);
}

const PORTSCAN_DEFAULT_TIMING = "T4";
const PORTSCAN_DEFAULT_SCAN_TYPE = "connect";
const SCAN_TYPE_FLAG = { connect: "-sT", syn: "-sS" };

function runPortScan(ip, opts = {}) {
  const timing = opts.timing || PORTSCAN_DEFAULT_TIMING;
  const portsArgs = opts.portsArgs || PORTS_DEFAULT_ARGS;
  const scanFlag = SCAN_TYPE_FLAG[opts.scanType || PORTSCAN_DEFAULT_SCAN_TYPE];
  const scriptsArgs = opts.scriptsArgs || [];
  // NSE adds variable wall time per script (banner waits, http probes,
  // ssh handshakes…). Bump the per-scan timeout when scripts are enabled
  // so a top-1000 + safe doesn't get killed mid-run.
  const timeoutMs = scriptsArgs.length ? 600_000 : 180_000;
  return new Promise((resolve, reject) => {
    // portsArgs: either ["--top-ports", N] (nmap's most common N TCP ports)
    //            or ["-p", "<spec>"] (explicit comma/range list).
    // scanFlag: -sT (default) for full TCP connect — "open" means a real
    //           handshake completed, no ambiguous filtered middle state.
    //           -sS for SYN scan — faster, more stealthy, but firewalls
    //           that drop SYN-ACK silently make some ports look unreachable.
    // -sV: service/version detection
    // -T<n>: timing template (T0 paranoid … T5 insane). Default T4.
    // --version-light: faster service probes (skip rare ones)
    // --reason: include why nmap classified each port (syn-ack, conn-refused,
    //           no-response…) so the UI can show the technical detail.
    // scriptsArgs: optional ["--script=default,safe"] — categories validated
    //              upstream, never user-provided strings.
    execFile(
      "nmap",
      [
        ...portsArgs,
        scanFlag,
        "-sV",
        `-${timing}`,
        "--version-light",
        "--reason",
        ...scriptsArgs,
        "-oX",
        "-",
        ip,
      ],
      { maxBuffer: 16 * 1024 * 1024, timeout: timeoutMs },
      (err, stdout, stderr) => {
        if (err) {
          const msg = stderr?.toString().trim() || err.message;
          return reject(new Error(`nmap failed: ${msg}`));
        }
        try {
          resolve({
            ports: parsePorts(stdout),
            host_scripts: parseHostScripts(stdout),
          });
        } catch (e) {
          reject(new Error(`failed to parse nmap output: ${e.message}`));
        }
      },
    );
  });
}

function runUdpPortScan(ip, opts = {}) {
  const timing = opts.timing || PORTSCAN_DEFAULT_TIMING;
  const portsArgs = opts.portsArgs || PORTS_DEFAULT_ARGS;
  return new Promise((resolve, reject) => {
    // -sU: UDP scan. Slow by nature: nmap waits on timeouts because UDP
    //      doesn't ack. Combined with -sV's per-service payloads (DNS,
    //      NTP, SNMP, mDNS…) to coax responses out of services that
    //      otherwise would never speak unsolicited.
    // Reuses portsArgs (--top-ports N | -p <spec>) and timing flags.
    // Timeout 30 min: a top-100 UDP scan against a single host can
    // realistically take 10-15 min on -T4.
    execFile(
      "nmap",
      [
        ...portsArgs,
        "-sU",
        "-sV",
        `-${timing}`,
        "--version-light",
        "--reason",
        "-oX",
        "-",
        ip,
      ],
      { maxBuffer: 16 * 1024 * 1024, timeout: 1_800_000 },
      (err, stdout, stderr) => {
        if (err) {
          const msg = stderr?.toString().trim() || err.message;
          return reject(new Error(`nmap failed: ${msg}`));
        }
        try {
          resolve(parsePorts(stdout));
        } catch (e) {
          reject(new Error(`failed to parse nmap output: ${e.message}`));
        }
      },
    );
  });
}

function parseOsMatches(xml) {
  const doc = xmlParser.parse(xml);
  const hosts = doc?.nmaprun?.host || [];
  const host = hosts[0];
  if (!host) return [];
  const matches = host.os?.osmatch || [];
  return matches.map((m) => {
    const cls = (m.osclass || [])[0] || {};
    return {
      name: m.name || "unknown",
      accuracy: parseInt(m.accuracy, 10) || 0,
      line: m.line ? parseInt(m.line, 10) : null,
      vendor: cls.vendor || null,
      family: cls.osfamily || null,
      gen: cls.osgen || null,
      type: cls.type || null,
    };
  });
}

function runOsScan(ip) {
  return new Promise((resolve, reject) => {
    // -O: OS detection (requires NET_RAW + NET_ADMIN, already in compose)
    // --osscan-guess: report best guesses when no perfect match (useful on LAN devices)
    // -T4: faster timing
    execFile(
      "nmap",
      ["-O", "--osscan-guess", "-T4", "-oX", "-", ip],
      { maxBuffer: 16 * 1024 * 1024, timeout: 180_000 },
      (err, stdout, stderr) => {
        if (err) {
          const msg = stderr?.toString().trim() || err.message;
          return reject(new Error(`nmap failed: ${msg}`));
        }
        try {
          resolve(parseOsMatches(stdout));
        } catch (e) {
          reject(new Error(`failed to parse nmap output: ${e.message}`));
        }
      },
    );
  });
}

module.exports = {
  validateCidr,
  validateIpv4,
  validateTiming,
  validatePortsSpec,
  validateScanType,
  validateScripts,
  validateDiscovery,
  runPingSweep,
  runPortScan,
  runUdpPortScan,
  runOsScan,
  parseHosts,
  parsePorts,
  parseHostScripts,
  parseOsMatches,
};
