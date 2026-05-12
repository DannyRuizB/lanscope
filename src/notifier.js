// v0.11.0 — dispatcher for notification channels.
//
// Three event types: scan_done / scan_error / scan_skipped. Two channel
// types: webhook (with generic / Discord / Slack payload formats) and
// ntfy.sh.
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

function titleFor(event) {
  if (event === "scan_done") return "Scheduled scan completed";
  if (event === "scan_error") return "Scheduled scan failed";
  if (event === "scan_skipped") return "Scheduled scan skipped";
  return `LanScope event: ${event}`;
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
  return `LanScope event: ${event}`;
}

function colorFor(event) {
  if (event === "scan_done") return 0x2ecc71;
  if (event === "scan_error") return 0xe74c3c;
  if (event === "scan_skipped") return 0xf1c40f;
  return 0x95a5a6;
}

function unicodeIconFor(event) {
  if (event === "scan_done") return "✓"; // ✓
  if (event === "scan_error") return "✗"; // ✗
  if (event === "scan_skipped") return "⊘"; // ⊘
  return "•"; // •
}

function slackEmojiFor(event) {
  if (event === "scan_done") return ":white_check_mark:";
  if (event === "scan_error") return ":x:";
  if (event === "scan_skipped") return ":warning:";
  return ":bell:";
}

function ntfyTagsFor(event) {
  if (event === "scan_done") return "white_check_mark";
  if (event === "scan_error") return "x";
  if (event === "scan_skipped") return "warning";
  return "bell";
}

function ntfyPriorityFor(event) {
  if (event === "scan_error") return "high";
  if (event === "scan_skipped") return "default";
  return "low";
}

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
        ? { id: context.scan.id, host_count: context.scan.host_count, started_at: context.scan.started_at }
        : null,
      error: context.error || null,
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
