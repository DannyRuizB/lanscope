// Optional HTTP Basic Auth (v1.6.0). LanScope's UI can start a scan against
// whatever network the container can reach, so an instance exposed beyond
// localhost deserves a lock. Enabled only when BOTH AUTH_USER and AUTH_PASS
// are set — the default stays open for the localhost/homelab case and the
// public demo. Everything is protected (static UI and API alike): the UI
// leaks the whole inventory, not just the mutating endpoints.
"use strict";

const crypto = require("node:crypto");

// Constant-time equality. timingSafeEqual demands equal-length buffers, so
// compare sha256 digests: fixed length, no early-exit on the first byte,
// and the length of the real secret never leaks through a branch.
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// "Basic base64(user:pass)" → {user, pass}, or null when malformed. The
// password may itself contain ':' — only the FIRST colon separates.
function parseBasicHeader(header) {
  if (typeof header !== "string") return null;
  const m = header.match(/^Basic +([A-Za-z0-9+/]+={0,2})$/i);
  if (!m) return null;
  const decoded = Buffer.from(m[1], "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep === -1) return null;
  return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
}

// Express middleware. Evaluates both comparisons unconditionally (no &&
// short-circuit on the user check) so a wrong username costs the same time
// as a wrong password.
function basicAuth({ user, pass }) {
  return (req, res, next) => {
    const creds = parseBasicHeader(req.headers.authorization);
    if (creds) {
      const userOk = safeEqual(creds.user, user);
      const passOk = safeEqual(creds.pass, pass);
      if (userOk && passOk) return next();
    }
    res.set("WWW-Authenticate", 'Basic realm="LanScope", charset="UTF-8"');
    res.status(401).json({ error: "Authentication required" });
  };
}

module.exports = { basicAuth, parseBasicHeader, safeEqual };
