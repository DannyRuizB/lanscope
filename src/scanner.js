const { execFile } = require("node:child_process");
const { XMLParser } = require("fast-xml-parser");

// CIDR validation: IPv4 a.b.c.d/n where n in [0,32]. Strict regex,
// no whitespace, no shell metacharacters reach nmap.
const CIDR_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(?:3[0-2]|[12]?\d)$/;

function validateCidr(cidr) {
  if (typeof cidr !== "string") return "cidr must be a string";
  if (!CIDR_RE.test(cidr)) return "invalid CIDR (expected IPv4 a.b.c.d/n)";
  return null;
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  isArray: (name) => name === "host" || name === "address" || name === "hostname",
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

module.exports = { validateCidr, runPingSweep, parseHosts };
