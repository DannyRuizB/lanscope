// v0.11.0 — dispatcher for notification channels.
//
// Event types:
//   scan_done / scan_error / scan_skipped — emitted by the scheduler.
//   baseline_diff (v0.13.0) — emitted by the runner after a successful scan
//     when the diff against the declared baseline produced at least one alert.
//   high_latency (v1.13.0) — emitted by the runner when LATENCY_ALERT_MS
//     flagged at least one host in the scan. Its own event (not part of the
//     baseline_diff digest): it makes no baseline claim, and a latency page
//     usually wants a different channel than an inventory-drift alarm.
//   daily_digest (v1.15.0) — emitted by the scheduler's digest cron (opt-in
//     via DIGEST_CRON): a once-a-day roll-up per CIDR of scans run, new
//     alerts and the pending backlog. The low-priority counterpart to the
//     per-event alerts — a morning summary, not a page.
//
// Channel types: webhook (with generic / Discord / Slack payload formats)
// and ntfy.sh.
//
// dispatch() is fire-and-forget for callers: the scheduler must not block
// (or fail) because a downstream webhook is slow or broken. Each channel's
// result is persisted via recordChannelDispatch so the UI can show "last
// sent ✓ HH:MM" / "✗ HTTP 503".
//
// DEMO_MODE short-circuits the dispatcher entirely so the Render demo never
// makes outbound calls.

const db = require("./db");

const FETCH_TIMEOUT_MS = 5000;
const DEMO_MODE = process.env.DEMO_MODE === "true";

// One row per event. Adding a fifth event = one new entry, not seven edits.
const EVENT_META = {
  scan_done: {
    title: "Scheduled scan completed",
    color: 0x2ecc71,
    icon: "✓",
    slackEmoji: ":white_check_mark:",
    ntfyTag: "white_check_mark",
    ntfyPriority: "low",
  },
  scan_error: {
    title: "Scheduled scan failed",
    color: 0xe74c3c,
    icon: "✗",
    slackEmoji: ":x:",
    ntfyTag: "x",
    ntfyPriority: "high",
  },
  scan_skipped: {
    title: "Scheduled scan skipped",
    color: 0xf1c40f,
    icon: "⊘",
    slackEmoji: ":warning:",
    ntfyTag: "warning",
    ntfyPriority: "default",
  },
  baseline_diff: {
    title: "Baseline divergence detected",
    color: 0xe67e22,
    icon: "⚠",
    slackEmoji: ":warning:",
    ntfyTag: "warning",
    ntfyPriority: "high",
  },
  sensitive_port: {
    title: "Sensitive port exposed",
    color: 0xdc2626, // red — the most actionable of the alert families
    icon: "🔓",
    slackEmoji: ":unlock:",
    ntfyTag: "unlock",
    ntfyPriority: "high",
  },
  high_latency: {
    title: "High latency detected",
    color: 0x6366f1, // indigo — matches the alert chip in the UI
    icon: "⏱",
    slackEmoji: ":hourglass:",
    ntfyTag: "hourglass",
    ntfyPriority: "default",
  },
  daily_digest: {
    title: "LanScope daily digest",
    color: 0x3498db,
    icon: "📊",
    slackEmoji: ":bar_chart:",
    ntfyTag: "bar_chart",
    ntfyPriority: "low",
  },
};

const FALLBACK_META = {
  color: 0x95a5a6,
  icon: "•",
  slackEmoji: ":bell:",
  ntfyTag: "bell",
  ntfyPriority: "low",
};

const metaFor = (event) => EVENT_META[event] || FALLBACK_META;

function titleFor(event) {
  return EVENT_META[event]?.title || `LanScope event: ${event}`;
}

function summaryFor(event, context) {
  const name = context.schedule?.name || "scan";
  const cidr = context.schedule?.cidr || context.scan?.cidr || "?";
  if (event === "scan_done") {
    const n = context.scan?.host_count ?? 0;
    return `Scheduled scan "${name}" completed: ${n} host${n === 1 ? "" : "s"} on ${cidr}`;
  }
  if (event === "scan_error") {
    return `Scheduled scan "${name}" failed on ${cidr}: ${context.error || "unknown error"}`;
  }
  if (event === "scan_skipped") {
    return `Scheduled scan "${name}" was skipped (${context.error || "another scan in progress"})`;
  }
  if (event === "baseline_diff") {
    const total = context.total ?? 0;
    const counts = context.counts || {};
    const parts = [];
    for (const k of db.ALERT_TYPES) {
      const v = counts[k] || 0;
      if (v > 0) parts.push(`${v} ${k.replace(/_/g, " ")}`);
    }
    const detail = parts.length ? ` — ${parts.join(", ")}` : "";
    return `Baseline divergence on ${cidr}: ${total} change${total === 1 ? "" : "s"}${detail}`;
  }
  if (event === "sensitive_port") {
    const n = context.total ?? 0;
    const first = (context.exposed_hosts || [])[0];
    const firstTxt = first
      ? ` (e.g. ${first.ip}: ${(first.ports || []).map((p) => p.port).join(", ")})`
      : "";
    return `Sensitive ports open on ${cidr}: ${n} host${n === 1 ? "" : "s"}${firstTxt}`;
  }
  if (event === "high_latency") {
    const n = context.total ?? 0;
    const t = context.threshold_ms;
    const worst = (context.slow_hosts || [])[0];
    const worstTxt = worst ? ` (worst: ${worst.ip} at ${worst.latency_ms} ms)` : "";
    return `High latency on ${cidr}: ${n} host${n === 1 ? "" : "s"} at or above ${t} ms${worstTxt}`;
  }
  if (event === "daily_digest") {
    const d = context.digest || {};
    const t = d.totals || {};
    const hours = context.window_hours ?? 24;
    if (!t.networks) {
      return `LanScope daily digest: no scans in the last ${hours}h`;
    }
    return (
      `LanScope daily digest (last ${hours}h): ${t.scans} scan${t.scans === 1 ? "" : "s"} ` +
      `across ${t.networks} network${t.networks === 1 ? "" : "s"}, ` +
      `${t.alerts_new} new alert${t.alerts_new === 1 ? "" : "s"}, ` +
      `${t.alerts_pending} still pending`
    );
  }
  return `LanScope event: ${event}`;
}

const colorFor = (event) => metaFor(event).color;
const unicodeIconFor = (event) => metaFor(event).icon;
const slackEmojiFor = (event) => metaFor(event).slackEmoji;
const ntfyTagsFor = (event) => metaFor(event).ntfyTag;
const ntfyPriorityFor = (event) => metaFor(event).ntfyPriority;

function buildWebhookGeneric(event, context) {
  return {
    body: JSON.stringify({
      event,
      timestamp: Date.now(),
      summary: summaryFor(event, context),
      schedule: context.schedule
        ? { id: context.schedule.id, name: context.schedule.name, cidr: context.schedule.cidr }
        : null,
      scan: context.scan
        ? {
            id: context.scan.id,
            cidr: context.scan.cidr ?? null,
            host_count: context.scan.host_count,
            started_at: context.scan.started_at,
          }
        : null,
      error: context.error || null,
      // v0.13.0 — baseline_diff aggregate fields. Always present (null when
      // the event doesn't carry them) so downstream consumers have a stable
      // shape.
      total: context.total ?? null,
      counts: context.counts ?? null,
      baseline: context.baseline ?? null,
      // v1.13.0 — high_latency fields, same stable-shape rule. slow_hosts is
      // capped at the 5 worst offenders; total says how many there really are.
      threshold_ms: context.threshold_ms ?? null,
      slow_hosts: context.slow_hosts ?? null,
      // v1.18.0 — sensitive_port fields, same stable-shape rule: the watchlist
      // that judged the scan and up to 5 exposed hosts (total says how many).
      watchlist: context.watchlist ?? null,
      exposed_hosts: context.exposed_hosts ?? null,
      // v1.15.0 — daily_digest roll-up (window + per-CIDR breakdown), null on
      // every other event so consumers keep a stable shape.
      window_hours: context.window_hours ?? null,
      digest: context.digest ?? null,
    }),
    headers: { "content-type": "application/json" },
  };
}

function buildWebhookDiscord(event, context) {
  return {
    body: JSON.stringify({
      username: "LanScope",
      embeds: [
        {
          title: `${unicodeIconFor(event)} ${titleFor(event)}`,
          description: summaryFor(event, context),
          color: colorFor(event),
          timestamp: new Date().toISOString(),
        },
      ],
    }),
    headers: { "content-type": "application/json" },
  };
}

function buildWebhookSlack(event, context) {
  return {
    body: JSON.stringify({
      text: `${slackEmojiFor(event)} *LanScope*: ${summaryFor(event, context)}`,
    }),
    headers: { "content-type": "application/json" },
  };
}

function buildNtfy(event, context) {
  return {
    body: summaryFor(event, context),
    headers: {
      "content-type": "text/plain",
      Title: titleFor(event),
      Tags: ntfyTagsFor(event),
      Priority: ntfyPriorityFor(event),
    },
  };
}

async function sendHttp(url, { body, headers }) {
  const res = await fetch(url, {
    method: "POST",
    body,
    headers,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}${res.statusText ? " " + res.statusText : ""}`);
  }
}

// Exported so the /test endpoint can fire a synthetic event against a single
// channel and await the result (the regular dispatch() is fire-and-forget).
async function sendToChannel(channel, event, context) {
  if (channel.type === "webhook") {
    const { format = "generic", url } = channel.config || {};
    if (!url) throw new Error("channel config.url missing");
    const payload =
      format === "discord"
        ? buildWebhookDiscord(event, context)
        : format === "slack"
          ? buildWebhookSlack(event, context)
          : buildWebhookGeneric(event, context);
    await sendHttp(url, payload);
    return;
  }
  if (channel.type === "ntfy") {
    const { topic, server } = channel.config || {};
    if (!topic) throw new Error("channel config.topic missing");
    const baseUrl = (server || "https://ntfy.sh").replace(/\/$/, "");
    await sendHttp(`${baseUrl}/${encodeURIComponent(topic)}`, buildNtfy(event, context));
    return;
  }
  throw new Error(`unsupported channel type: ${channel.type}`);
}

// Fan out to every enabled channel subscribed to this event. Errors from one
// channel never affect siblings (allSettled) and never propagate out (caller
// only needs to know whether the dispatch was attempted).
async function dispatch(event, context = {}) {
  if (DEMO_MODE) return { skipped: true, reason: "demo mode" };
  const channels = db.listEnabledChannelsForEvent(event);
  if (!channels.length) return { sent: 0 };
  await Promise.allSettled(
    channels.map(async (ch) => {
      try {
        await sendToChannel(ch, event, context);
        db.recordChannelDispatch(ch.id, { status: "done" });
      } catch (e) {
        console.error(`[notifier] channel ${ch.id} (${ch.name}) failed for ${event}: ${e.message}`);
        db.recordChannelDispatch(ch.id, { status: "error", error: e.message });
      }
    }),
  );
  return { sent: channels.length };
}

module.exports = { dispatch, sendToChannel };
