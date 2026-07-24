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

const ALLOWED_EVENTS = new Set([
  "scan_done",
  "scan_error",
  "scan_skipped",
  "baseline_diff", // v0.13.0
  "high_latency", // v1.13.0
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

module.exports = {
  validateScheduleName,
  validateCronExpr,
  validateKeepLast,
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
