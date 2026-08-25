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

// ===== API tokens (v1.25.0) =====
// Basic Auth guards the browser, but handing the admin password to every
// cron job and script that polls the API is how the password ends up in
// shell history and crontabs. A token is a second door with its own key:
// mintable, listable and revocable one by one, without ever touching the
// admin credential.

// "lsk_" + 64 hex chars (32 random bytes). The prefix makes a leaked token
// recognizable in logs and secret scanners; the body is crypto-random.
const TOKEN_RE = /^lsk_[0-9a-f]{64}$/;

function generateToken() {
  return `lsk_${crypto.randomBytes(32).toString("hex")}`;
}

// Only the sha256 of the token is ever stored — a read of the database (a
// backup, a stray copy) yields nothing presentable. Lookup happens by hash
// equality: an attacker controls the preimage, not the digest, so a timing
// difference in the index probe tells them nothing they can steer.
function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

// "Bearer lsk_…" → the token string, or null. Anything not shaped exactly
// like one of our tokens is rejected before touching the database.
function parseBearerHeader(header) {
  if (typeof header !== "string") return null;
  const m = header.match(/^Bearer +(\S+)$/i);
  if (!m) return null;
  return TOKEN_RE.test(m[1]) ? m[1] : null;
}

// Combined middleware: a valid API token OR the Basic credential opens the
// door. Token first — it's cheap to rule out (regex + one indexed lookup)
// and API clients never see the browser's Basic prompt semantics change.
function requireAuth({ user, pass, findTokenByHash, markTokenUsed }) {
  const basic = basicAuth({ user, pass });
  return (req, res, next) => {
    const token = parseBearerHeader(req.headers.authorization);
    if (token) {
      const row = findTokenByHash(hashToken(token));
      if (row) {
        // A refused write below is still a USE — the token authenticated
        // fine — and last_used_at answers "is anyone holding this token?",
        // so the stamp comes first.
        markTokenUsed(row.id);
        // v1.30.0 — scope. A read-only token may ask anything but change
        // nothing: the same GET/HEAD/OPTIONS trio DEMO_MODE lets through.
        // Deliberately a NAMED 403, not the bare 401: the single bare 401
        // is for invalid credentials (nothing to enumerate); this caller
        // proved identity, and "your token is read-only" is the answer to
        // why the cron broke — the visible-expiry philosophy applied to
        // writes.
        if (row.scope === "read" && !["GET", "HEAD", "OPTIONS"].includes(req.method)) {
          return res.status(403).json({
            error: 'this token is read-only (scope "read") — it can GET everything but change nothing',
          });
        }
        return next();
      }
      // A malformed, revoked or EXPIRED token falls through to the same 401
      // the Basic path produces — one failure shape, nothing to enumerate
      // (expiry is enforced in the lookup itself; see db.findApiTokenByHash).
    }
    return basic(req, res, next);
  };
}

module.exports = {
  basicAuth,
  parseBasicHeader,
  safeEqual,
  generateToken,
  hashToken,
  parseBearerHeader,
  requireAuth,
};
