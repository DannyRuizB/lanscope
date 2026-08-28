// Scan diff (v1.33.0) — the appeared / disappeared / changed classification
// behind the compare view, extracted from app.js so the SAME code serves the
// browser (window.ScanDiff) and the server's diff export (module.exports):
// what you download is what the compare view showed you, by construction —
// the host-search.js dual-export pattern.
(function (global) {
  "use strict";

  // Coarse OS family bucket. "unknown" both when the host was never
  // OS-scanned and when nmap had no match — the diff only calls an OS
  // change real when BOTH sides have a known bucket.
  function osBucketKey(host) {
    if (!host.osscanned_at) return "unknown";
    const top = (host.os_matches || [])[0];
    if (!top) return "unknown";
    const f = (top.family || "").toLowerCase();
    if (f.includes("windows")) return "windows";
    if (f.includes("linux")) return "linux";
    if (f.includes("mac") || f.includes("ios") || f.includes("apple")) return "apple";
    return "other";
  }

  function hostChangeReasons(b, n) {
    const reasons = [];
    if ((b.mac || "") !== (n.mac || "")) reasons.push("mac");
    if ((b.hostname || "") !== (n.hostname || "")) reasons.push("hostname");
    if (b.osscanned_at && n.osscanned_at) {
      const bk = osBucketKey(b);
      const nk = osBucketKey(n);
      if (bk !== nk && bk !== "unknown" && nk !== "unknown") reasons.push("os");
    }
    return reasons;
  }

  // Both scans as served by the API. Only hosts that were UP count on
  // either side ("down" rows are absence, not presence). byIp powers the
  // UI's per-row classes; the arrays power the banner counts and the export.
  function diffScans(baseScan, newScan) {
    const baseUp = (baseScan?.hosts || []).filter((h) => h.status === "up");
    const newUp  = (newScan?.hosts  || []).filter((h) => h.status === "up");
    const baseByIp = new Map(baseUp.map((h) => [h.ip, h]));
    const newByIp  = new Map(newUp.map((h) => [h.ip, h]));
    const appeared = [];
    const disappeared = [];
    const changed = [];
    const unchanged = [];
    const byIp = new Map(); // ip -> { state, reasons? }
    for (const n of newUp) {
      const b = baseByIp.get(n.ip);
      if (!b) {
        appeared.push(n);
        byIp.set(n.ip, { state: "appeared" });
      } else {
        const reasons = hostChangeReasons(b, n);
        if (reasons.length) {
          changed.push({ host: n, base: b, reasons });
          byIp.set(n.ip, { state: "changed", reasons });
        } else {
          unchanged.push(n);
          byIp.set(n.ip, { state: "unchanged" });
        }
      }
    }
    for (const b of baseUp) {
      if (!newByIp.has(b.ip)) {
        disappeared.push(b);
        byIp.set(b.ip, { state: "disappeared" });
      }
    }
    return { appeared, disappeared, changed, unchanged, byIp };
  }

  const api = { diffScans, hostChangeReasons, osBucketKey };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.ScanDiff = api;
})(typeof window !== "undefined" ? window : globalThis);
