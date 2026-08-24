// Pure request validators for the HTTP layer (schedules + notification
// channels). Kept out of server.js so they can be unit-tested the same way
// scanner.js's validators are — these guard security-relevant input (webhook
// URL schemes, ntfy topics, cron expressions), so they deserve coverage.
//
// Each returns { value } on success or { error } on failure, except
// validateHttpUrl which returns the string or null.

const cron = require("node-cron");

function validateScheduleName(s) {
  if (typeof s !== "string") return { error: "name is required" };
  const name = s.trim();
  if (name.length === 0) return { error: "name cannot be empty" };
  if (name.length > 80) return { error: "name too long (max 80 chars)" };
  return { value: name };
}

// v1.25.0 — an API token's name is its identity in the list ("backup-cron",
// "grafana"): required, trimmed, and short enough to read in a table row.
function validateTokenName(s) {
  if (typeof s !== "string") return { error: "name is required" };
  const name = s.trim();
  if (name.length === 0) return { error: "name cannot be empty" };
  if (name.length > 64) return { error: "name too long (max 64 chars)" };
  return { value: name };
}

function validateCronExpr(s) {
  if (typeof s !== "string" || s.trim().length === 0) {
    return { error: "cron_expr is required" };
  }
  const expr = s.trim();
  if (!cron.validate(expr)) return { error: "invalid cron expression" };
  return { value: expr };
}

// v1.8.0 — per-schedule retention. null/absent means "keep every scan".
// The cap is a sanity bound, not a real limit — 10000 hourly scans is over
// a year of history; anything above that is a typo, not a policy.
const KEEP_LAST_MAX = 10000;
function validateKeepLast(v) {
  if (v === null || v === undefined) return { value: null };
  if (!Number.isInteger(v) || v < 1 || v > KEEP_LAST_MAX) {
    return { error: `keep_last must be an integer between 1 and ${KEEP_LAST_MAX}, or null` };
  }
  return { value: v };
}

// v1.14.0 — per-schedule latency threshold. Three-valued on purpose:
// null = inherit the global LATENCY_ALERT_MS, 0 = alerts explicitly OFF for
// this schedule, N > 0 = own threshold. The cap matches sanity, not physics:
// a 10-minute RTT is a typo.
const LATENCY_ALERT_MAX_MS = 600000;
function validateLatencyAlertMs(v) {
  if (v === null || v === undefined) return { value: null };
  if (!Number.isInteger(v) || v < 0 || v > LATENCY_ALERT_MAX_MS) {
    return {
      error: `latency_alert_ms must be an integer between 0 and ${LATENCY_ALERT_MAX_MS} (0 = off), or null to inherit the global threshold`,
    };
  }
  return { value: v };
}

const ALLOWED_EVENTS = new Set([
  "scan_done",
  "scan_error",
  "scan_skipped",
  "baseline_diff", // v0.13.0
  "high_latency", // v1.13.0
  "sensitive_port", // v1.18.0
  "daily_digest", // v1.15.0
]);
const ALLOWED_CHANNEL_TYPES = new Set(["webhook", "ntfy"]);
const ALLOWED_WEBHOOK_FORMATS = new Set(["generic", "discord", "slack"]);

function validateChannelName(s) {
  if (typeof s !== "string") return { error: "name is required" };
  const v = s.trim();
  if (v.length === 0) return { error: "name cannot be empty" };
  if (v.length > 80) return { error: "name too long (max 80 chars)" };
  return { value: v };
}

function validateChannelType(s) {
  if (!ALLOWED_CHANNEL_TYPES.has(s)) {
    return { error: `type must be one of: ${Array.from(ALLOWED_CHANNEL_TYPES).join(", ")}` };
  }
  return { value: s };
}

function validateHttpUrl(s) {
  if (typeof s !== "string") return null;
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return s;
  } catch {
    return null;
  }
}

function validateChannelConfig(type, config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return { error: "config is required" };
  }
  if (type === "webhook") {
    if (!validateHttpUrl(config.url)) {
      return { error: "config.url must be a valid http(s) URL" };
    }
    const format = config.format == null ? "generic" : config.format;
    if (!ALLOWED_WEBHOOK_FORMATS.has(format)) {
      return {
        error: `config.format must be one of: ${Array.from(ALLOWED_WEBHOOK_FORMATS).join(", ")}`,
      };
    }
    return { value: { url: config.url, format } };
  }
  if (type === "ntfy") {
    if (typeof config.topic !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(config.topic)) {
      return { error: "config.topic must be 1..64 chars (letters, digits, _ or -)" };
    }
    const server = config.server == null ? "https://ntfy.sh" : validateHttpUrl(config.server);
    if (!server) return { error: "config.server must be a valid http(s) URL" };
    return { value: { topic: config.topic, server } };
  }
  return { error: "unknown type" };
}

function validateChannelEvents(events) {
  if (!Array.isArray(events)) return { error: "events must be an array" };
  if (events.length === 0) return { error: "events cannot be empty" };
  const bad = events.find((e) => typeof e !== "string" || !ALLOWED_EVENTS.has(e));
  if (bad) {
    return {
      error: `event not allowed: ${bad}. Use one of: ${Array.from(ALLOWED_EVENTS).join(", ")}`,
    };
  }
  // dedupe preserving order
  const seen = new Set();
  const out = [];
  for (const e of events) {
    if (!seen.has(e)) {
      seen.add(e);
      out.push(e);
    }
  }
  return { value: out };
}

// ----- Host labels (v1.3.0) ------------------------------------------------
// A label is a short display name; notes are free text. Both optional —
// clearing both is how a label is removed — but when present they are
// trimmed and length-capped so the table and the CSV export stay sane.
function validateLabelText(s) {
  if (s == null) return { value: null };
  if (typeof s !== "string") return { error: "label must be a string" };
  const v = s.trim();
  if (v.length === 0) return { value: null };
  if (v.length > 64) return { error: "label too long (max 64 chars)" };
  return { value: v };
}

function validateNotesText(s) {
  if (s == null) return { value: null };
  if (typeof s !== "string") return { error: "notes must be a string" };
  const v = s.trim();
  if (v.length === 0) return { value: null };
  if (v.length > 500) return { error: "notes too long (max 500 chars)" };
  return { value: v };
}

// The ?sections= query, shared by selective export (v1.26) and selective
// import (v1.27): it names which config sections an operation touches. Same
// vocabulary either way — on export it picks what the backup carries, on
// import what gets restored — and both compose because the import already
// treats an absent section as "nothing to do here".
const CONFIG_SECTIONS = ["labels", "mutes", "schedules", "channels"];

function validateSectionsParam(raw) {
  // Absent means everything — the pre-v1.26 contract, unchanged.
  if (raw === undefined) return { value: null };
  if (typeof raw !== "string") {
    return { error: "sections must be a single comma-separated list" };
  }
  const tokens = raw.split(",").map((t) => t.trim()).filter((t) => t.length > 0);
  if (tokens.length === 0) {
    return { error: "sections is empty — omit the parameter to act on everything" };
  }
  for (const t of tokens) {
    if (!CONFIG_SECTIONS.includes(t)) {
      return { error: `unknown section: ${t} (valid: ${CONFIG_SECTIONS.join(", ")})` };
    }
  }
  // Deduped, in canonical order — and the full set collapses to null so
  // "everything" has exactly one spelling (the mute-types precedent).
  const picked = CONFIG_SECTIONS.filter((s) => tokens.includes(s));
  if (picked.length === CONFIG_SECTIONS.length) return { value: null };
  return { value: picked };
}

// v1.23.0 — config import. Validates the WHOLE document before anything is
// written (the import itself is one db transaction): a config restore is
// all-or-nothing, never half a backup. Dependencies are injected so this
// stays a pure module — validateCidr/validateIpv4 live in the scanner and
// the scan-options validator in the scheduler, and dragging either in here
// would tie the unit tests to nmap and node-cron wiring.
function validateConfigDoc(doc, deps) {
  const { validateCidr, validateIpv4, validateScanOptions, alertTypes } = deps;
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { error: "body must be a config export object" };
  }
  if (doc.lanscope_config !== 1) {
    return { error: "not a LanScope config export (expected lanscope_config: 1)" };
  }
  const sections = {};
  for (const key of ["labels", "mutes", "schedules", "channels"]) {
    const v = doc[key];
    if (v === undefined || v === null) {
      sections[key] = [];
    } else if (!Array.isArray(v)) {
      return { error: `${key} must be an array` };
    } else {
      sections[key] = v;
    }
  }
  const out = { labels: [], mutes: [], schedules: [], channels: [] };
  const typeSet = new Set(alertTypes);

  for (const [i, l] of sections.labels.entries()) {
    const where = `labels[${i}]`;
    if (!l || typeof l !== "object") return { error: `${where} must be an object` };
    const cidrErr = validateCidr(l.cidr);
    if (cidrErr) return { error: `${where}: ${cidrErr}` };
    const ipErr = validateIpv4(l.ip);
    if (ipErr) return { error: `${where}: ${ipErr}` };
    const lblV = validateLabelText(l.label ?? "");
    if (lblV.error) return { error: `${where}: ${lblV.error}` };
    const ntsV = validateNotesText(l.notes ?? "");
    if (ntsV.error) return { error: `${where}: ${ntsV.error}` };
    out.labels.push({ cidr: l.cidr, ip: l.ip, label: lblV.value, notes: ntsV.value });
  }

  for (const [i, m] of sections.mutes.entries()) {
    const where = `mutes[${i}]`;
    if (!m || typeof m !== "object") return { error: `${where} must be an object` };
    const cidrErr = validateCidr(m.cidr);
    if (cidrErr) return { error: `${where}: ${cidrErr}` };
    const ipErr = validateIpv4(m.ip);
    if (ipErr) return { error: `${where}: ${ipErr}` };
    let types = null;
    if (m.types !== undefined && m.types !== null) {
      if (!Array.isArray(m.types) || m.types.length === 0) {
        return { error: `${where}: types must be a non-empty array of alert types, or null` };
      }
      const unique = [...new Set(m.types)];
      for (const t of unique) {
        if (!typeSet.has(t)) return { error: `${where}: unknown alert type: ${t}` };
      }
      types = unique.length === alertTypes.length ? null : unique;
    }
    let expires = null;
    if (m.expires_at !== undefined && m.expires_at !== null) {
      if (!Number.isInteger(m.expires_at)) {
        return { error: `${where}: expires_at must be an epoch-ms integer or null` };
      }
      // A deadline already in the past is legal here, unlike on the live
      // endpoint: a backup is a snapshot, and the lazy purge retires the
      // row on its first read after import.
      expires = m.expires_at;
    }
    out.mutes.push({ cidr: m.cidr, ip: m.ip, types, expires_at: expires });
  }

  for (const [i, s] of sections.schedules.entries()) {
    const where = `schedules[${i}]`;
    if (!s || typeof s !== "object") return { error: `${where} must be an object` };
    const nameV = validateScheduleName(s.name);
    if (nameV.error) return { error: `${where}: ${nameV.error}` };
    const cidrErr = validateCidr(s.cidr);
    if (cidrErr) return { error: `${where}: ${cidrErr}` };
    const cronV = validateCronExpr(s.cron_expr);
    if (cronV.error) return { error: `${where}: ${cronV.error}` };
    const optsV = validateScanOptions(s.scan_options ?? null);
    if (optsV.error) return { error: `${where}: ${optsV.error}` };
    const keepV = validateKeepLast(s.keep_last);
    if (keepV.error) return { error: `${where}: ${keepV.error}` };
    const latencyV = validateLatencyAlertMs(s.latency_alert_ms);
    if (latencyV.error) return { error: `${where}: ${latencyV.error}` };
    out.schedules.push({
      name: nameV.value,
      cidr: s.cidr,
      cron_expr: cronV.value,
      enabled: s.enabled !== false,
      scan_options: s.scan_options ?? null,
      keep_last: keepV.value,
      latency_alert_ms: latencyV.value,
    });
  }

  for (const [i, c] of sections.channels.entries()) {
    const where = `channels[${i}]`;
    if (!c || typeof c !== "object") return { error: `${where} must be an object` };
    const nameV = validateChannelName(c.name);
    if (nameV.error) return { error: `${where}: ${nameV.error}` };
    const typeV = validateChannelType(c.type);
    if (typeV.error) return { error: `${where}: ${typeV.error}` };
    const confV = validateChannelConfig(typeV.value, c.config);
    if (confV.error) return { error: `${where}: ${confV.error}` };
    const eventsV = validateChannelEvents(c.events);
    if (eventsV.error) return { error: `${where}: ${eventsV.error}` };
    out.channels.push({
      name: nameV.value,
      type: typeV.value,
      config: confV.value,
      events: eventsV.value,
      enabled: c.enabled !== false,
    });
  }

  return { value: out };
}

// v1.29.0 — a token that never expires is a password with extra steps, but
// FORCING an expiry breaks the homelab cron nobody rotates: optional.
// Absent / null / "" keeps the v1.25 behaviour (never expires). Otherwise a
// whole number of days, 1..3650 — ten years is "effectively never" said out
// loud. Relative on purpose (the server computes the deadline from its own
// clock at mint time): a mint is a one-shot, so the absolute-deadline
// round-trip argument that made mute snoozes take `until` does not apply.
function validateTokenTtlDays(v) {
  if (v === undefined || v === null || v === "") return { value: null };
  const n = typeof v === "number" ? v : Number(String(v).trim());
  if (!Number.isInteger(n) || n < 1 || n > 3650) {
    return {
      error:
        "expires_in_days must be a whole number of days between 1 and 3650 (omit it for a token that never expires)",
    };
  }
  return { value: n };
}

module.exports = {
  validateConfigDoc,
  validateSectionsParam,
  CONFIG_SECTIONS,
  validateScheduleName,
  validateTokenName,
  validateTokenTtlDays,
  validateCronExpr,
  validateKeepLast,
  validateLatencyAlertMs,
  validateChannelName,
  validateChannelType,
  validateHttpUrl,
  validateChannelConfig,
  validateChannelEvents,
  validateLabelText,
  validateNotesText,
  ALLOWED_EVENTS,
  ALLOWED_CHANNEL_TYPES,
  ALLOWED_WEBHOOK_FORMATS,
};
