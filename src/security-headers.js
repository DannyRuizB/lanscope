// v1.53.0 — Security headers on every response.
//
// LanScope's UI is the inventory of a network and a button that runs nmap
// against it, so the browser should be told as plainly as possible not to
// frame it, not to run script it didn't ship, and not to guess content types.
// Until now no response carried any of that: the page could be framed by any
// site (clickjacking a "Scan now" or "Delete scan" click), and a stored-XSS
// slip in the rendering of nmap output (hostnames, banners, NSE output) would
// have run with nothing in its way.
//
// The CSP is built from what the pages actually load:
//   - script: our own files, the two pinned CDN libraries (cytoscape, chart.js
//     on cdn.jsdelivr.net), and the inline scripts in index.html / login.html
//     allowed by their sha256 hash — computed here from the files themselves
//     at startup, so editing an inline script cannot silently break the page.
//   - style: 'self' plus 'unsafe-inline' — the UI builds markup with style
//     attributes; style injection is a much smaller risk than script, and the
//     script side is the one this policy is about.
//   - connect: 'self' only (the UI talks to its own API and nothing else).
//   - frame-ancestors 'none' + X-Frame-Options DENY: never framed.
// No HSTS: the homelab case is plain HTTP, and HSTS belongs on the TLS proxy
// SECURITY.md already recommends.
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const CDN = "https://cdn.jsdelivr.net";

// sha256 hashes of every inline <script> (no src attribute) in the given HTML.
function inlineScriptHashes(html) {
  const hashes = [];
  const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (m[1] && /\ssrc\s*=/i.test(m[1])) continue;
    const digest = crypto.createHash("sha256").update(m[2], "utf8").digest("base64");
    hashes.push(`'sha256-${digest}'`);
  }
  return hashes;
}

function buildCsp(scriptHashes) {
  return [
    "default-src 'self'",
    `script-src 'self' ${CDN} ${scriptHashes.join(" ")}`.trim(),
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

function securityHeaders({ publicDir = path.join(__dirname, "public"), pages = ["index.html", "login.html"] } = {}) {
  const hashes = [];
  for (const page of pages) {
    const html = fs.readFileSync(path.join(publicDir, page), "utf8");
    for (const h of inlineScriptHashes(html)) if (!hashes.includes(h)) hashes.push(h);
  }
  const csp = buildCsp(hashes);
  return function setSecurityHeaders(req, res, next) {
    res.setHeader("Content-Security-Policy", csp);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    next();
  };
}

module.exports = { securityHeaders, buildCsp, inlineScriptHashes };
