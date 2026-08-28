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

// ===== Session cookies (v1.34.0) =====
// Basic Auth works but the browser experience is a native prompt with no
// log-out and a fresh challenge on every 401. A signed session cookie gives
// a real login form and a real log-out — and stays STATELESS (no sessions
// table): the cookie carries its own {user, expiry} payload plus an HMAC, so
// a tampered or expired cookie is rejected by the signature check alone.
//
// The signing key is derived from the admin password, so rotating AUTH_PASS
// invalidates every outstanding session for free (a SESSION_SECRET override
// exists for anyone who wants sessions to survive a password change).
const SESSION_COOKIE = "lanscope_session";

function sessionKey({ pass, secret }) {
  return crypto.createHash("sha256").update(`lanscope-session\0${secret || pass}`).digest();
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A cookie is `<b64url(payload)>.<b64url(hmac)>`, payload = {u, exp} (exp in
// epoch-ms). ttlMs bounds how long the login lasts.
function makeSessionCookie({ user, ttlMs, pass, secret, now = Date.now() }) {
  const payload = b64url(JSON.stringify({ u: user, exp: now + ttlMs }));
  const mac = b64url(crypto.createHmac("sha256", sessionKey({ pass, secret })).update(payload).digest());
  return `${payload}.${mac}`;
}

// Verify signature FIRST (constant-time), then expiry, then the username.
// Returns the user on success, null on anything wrong — one failure shape.
function verifySessionCookie({ value, pass, secret, now = Date.now() }) {
  if (typeof value !== "string" || !value.includes(".")) return null;
  const dot = value.indexOf(".");
  const payload = value.slice(0, dot);
  const mac = value.slice(dot + 1);
  const expected = b64url(crypto.createHmac("sha256", sessionKey({ pass, secret })).update(payload).digest());
  const macBuf = Buffer.from(mac);
  const expBuf = Buffer.from(expected);
  if (macBuf.length !== expBuf.length || !crypto.timingSafeEqual(macBuf, expBuf)) return null;
  let data;
  try {
    data = JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
  if (!data || typeof data.u !== "string" || typeof data.exp !== "number") return null;
  if (now >= data.exp) return null;
  return data.u;
}

// Pull one cookie value out of a Cookie header. No dependency: split on ';',
// match our name, return the raw value (or null).
function readCookie(header, name) {
  if (typeof header !== "string") return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
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

// ===== Network binding (v1.31.0) =====
// The peer address as the binding sees it. IPv4-mapped IPv6 (::ffff:a.b.c.d,
// what a dual-stack listener reports for every v4 client) is unmapped, and
// ::1 is treated as the loopback it is. A genuinely-IPv6 peer keeps its
// address and simply never matches a v4 CIDR — the mint validator says so.
// Behind a reverse proxy this is the PROXY's address, deliberately: a
// forwarded header is attacker-writable, and a binding that trusts it
// would be theatre.
function clientAddress(req) {
  const raw = (req.socket && req.socket.remoteAddress) || "";
  if (raw.startsWith("::ffff:")) return raw.slice(7);
  if (raw === "::1") return "127.0.0.1";
  return raw;
}

function ipv4ToInt(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

// True when the IPv4 address falls inside the CIDR. Anything unparseable —
// an IPv6 peer, a malformed stored value — is NOT in the network: the
// binding fails closed.
function ipInCidr(ip, cidr) {
  const [net, prefixStr] = String(cidr).split("/");
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(net);
  const prefix = Number(prefixStr);
  if (ipInt === null || netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// Combined middleware: a valid API token OR the Basic credential opens the
// door. Token first — it's cheap to rule out (regex + one indexed lookup)
// and API clients never see the browser's Basic prompt semantics change.
function requireAuth({ user, pass, secret, findTokenByHash, markTokenUsed }) {
  const basic = basicAuth({ user, pass });
  return (req, res, next) => {
    // v1.34.0 — a valid session cookie opens the door too (the browser's
    // login-form path). A session is always full-access — it IS the admin
    // credential, re-presented — so no scope/binding logic, just verify and
    // pass. Checked before the token/Basic paths because a logged-in browser
    // sends it on every request.
    const cookieUser = verifySessionCookie({
      value: readCookie(req.headers.cookie, SESSION_COOKIE),
      pass,
      secret,
    });
    if (cookieUser !== null) return next();

    const token = parseBearerHeader(req.headers.authorization);
    if (token) {
      const row = findTokenByHash(hashToken(token));
      if (row) {
        // v1.31.0 — network binding, enforced BEFORE the use-stamp and with
        // the bare 401, deliberately inverting the scope decision: expiry
        // and scope favour debuggability once identity is proven, but a
        // binding is an anti-theft control — presented off its network, the
        // token must be indistinguishable from garbage. No named error that
        // confirms the token works, no last_used_at stamp a thief can trip.
        // The owner's answer to "why did my cron break" is the binding
        // shown in the token list.
        if (row.bound_cidr && !ipInCidr(clientAddress(req), row.bound_cidr)) {
          return basic(req, res, next);
        }
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
  clientAddress,
  ipInCidr,
  SESSION_COOKIE,
  makeSessionCookie,
  verifySessionCookie,
  readCookie,
};
