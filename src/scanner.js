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

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  isArray: (name) =>
    name === "host" ||
    name === "address" ||
    name === "hostname" ||
    name === "port" ||
    name === "osmatch" ||
    name === "osclass",
});

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

function runPingSweep(cidr) {
  return new Promise((resolve, reject) => {
    // -sn: ping scan, no port scan
    // -n: no DNS resolution from nmap (we get rDNS via PTR if available; -n is faster)
    //     ...actually we DO want PTR for hostnames, so omit -n.
    // -oX -: XML output to stdout
    // -T4: faster timing
    execFile(
      "nmap",
      ["-sn", "-T4", "-oX", "-", cidr],
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
    };
  });
}

const PORTSCAN_DEFAULT_TIMING = "T4";

function runPortScan(ip, opts = {}) {
  const timing = opts.timing || PORTSCAN_DEFAULT_TIMING;
  return new Promise((resolve, reject) => {
    // --top-ports 100: nmap's most common 100 TCP ports
    // -sT: full TCP connect scan — open means a real handshake completed,
    //      so users get a binary "accessible / not available" answer instead
    //      of the SYN-scan ambiguity (filtered ≠ confirmed unreachable).
    // -sV: service/version detection
    // -T<n>: timing template (T0 paranoid … T5 insane). Default T4.
    // --version-light: faster service probes (skip rare ones)
    // --reason: include why nmap classified each port (syn-ack, conn-refused,
    //           no-response…) so the UI can show the technical detail.
    execFile(
      "nmap",
      [
        "--top-ports",
        "100",
        "-sT",
        "-sV",
        `-${timing}`,
        "--version-light",
        "--reason",
        "-oX",
        "-",
        ip,
      ],
      { maxBuffer: 16 * 1024 * 1024, timeout: 180_000 },
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
  runPingSweep,
  runPortScan,
  runOsScan,
  parseHosts,
  parsePorts,
  parseOsMatches,
};
