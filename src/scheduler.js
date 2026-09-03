// v0.10.0 — node-cron scheduler for periodic CIDR scans.
//
// Lifecycle: server calls init() on boot, which loads every enabled schedule
// row and registers a cron task per row. Mutations to schedules (create,
// patch, delete) must call reload() so the running task set matches the DB.
//
// Concurrency: the runner module owns the actual lock; this module just
// translates a busy result into a "skipped" schedule run.

const cron = require("node-cron");
const db = require("./db");
const alerts = require("./alerts");
const { validateDiscovery, validateExclude } = require("./scanner");
const { executeCidrScan } = require("./runner");
const notifier = require("./notifier");

const tasks = new Map(); // schedule.id -> cron task
let digestTask = null; // the daily-digest cron task (v1.15.0), if enabled

// v1.15.0 — how many hours back the digest rolls up. Strict parse: a bad or
// non-positive value falls back to 24 rather than a window that captures
// nothing (or everything).
function digestWindowHours() {
  const raw = (process.env.DIGEST_WINDOW_HOURS || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 24;
}

// Build the roll-up and fire one daily_digest event. Exported so a test (and
// a future "send now" button) can trigger it without waiting for the cron.
async function runDigest() {
  const hours = digestWindowHours();
  const since = Date.now() - hours * 3600 * 1000;
  const digest = db.getDigest(since);
  return notifier.dispatch("daily_digest", { window_hours: hours, digest });
}

// Same shape as validateDiscovery() exposes, but scoped to the persisted
// `scan_options` blob. `discovery` (v0.10) and `exclude` (v1.36) are honoured;
// unknown keys ride along untouched. Lives here so server.js (HTTP) and
// scheduler ticks share one validator. Returns { args, excludeArgs } or { error }.
function validateScheduleScanOptions(opts) {
  if (opts == null) return { args: [], excludeArgs: [] };
  if (typeof opts !== "object" || Array.isArray(opts)) {
    return { error: "scan_options must be an object" };
  }
  let args = [];
  if (Object.prototype.hasOwnProperty.call(opts, "discovery")) {
    const disc = validateDiscovery(opts.discovery);
    if (disc.error) return { error: `discovery: ${disc.error}` };
    args = disc.args;
  }
  let excludeArgs = [];
  if (Object.prototype.hasOwnProperty.call(opts, "exclude")) {
    const ex = validateExclude(opts.exclude);
    if (ex.error) return { error: `exclude: ${ex.error}` };
    excludeArgs = ex.args;
  }
  return { args, excludeArgs };
}

// Run one schedule end-to-end: validate options, execute, record the run.
// Returns a normalized result the caller can inspect (used by run-now to
// build its HTTP response; cron ticks ignore it).
async function runScheduled(schedule) {
  const optsV = validateScheduleScanOptions(schedule.scan_options);
  if (optsV.error) {
    db.recordScheduleRun(schedule.id, {
      status: "error",
      error: `invalid scan_options: ${optsV.error}`,
    });
    return { status: "error", error: optsV.error };
  }

  const result = await executeCidrScan(schedule.cidr, {
    discoveryArgs: optsV.args,
    excludeArgs: optsV.excludeArgs,
    scheduleId: schedule.id,
  });

  if (result.busy) {
    db.recordScheduleRun(schedule.id, {
      status: "skipped",
      error: "another scan in progress",
    });
    notifier
      .dispatch("scan_skipped", { schedule, error: "another scan in progress" })
      .catch((e) => console.error(`[scheduler] notify scan_skipped failed: ${e.message}`));
    return { status: "skipped", error: "another scan in progress" };
  }
  if (result.error) {
    db.recordScheduleRun(schedule.id, {
      scan_id: result.scanId,
      status: "error",
      error: result.error,
    });
    notifier
      .dispatch("scan_error", { schedule, error: result.error, scan: { id: result.scanId } })
      .catch((e) => console.error(`[scheduler] notify scan_error failed: ${e.message}`));
    return { status: "error", scanId: result.scanId, error: result.error };
  }
  db.recordScheduleRun(schedule.id, {
    scan_id: result.scanId,
    status: "done",
  });
  // v1.8.0 — retention: prune AFTER recording the run, so last_scan_id points
  // at the scan that was just kept. A prune failure never taints the run —
  // the scan itself succeeded; log and move on.
  if (Number.isInteger(schedule.keep_last) && schedule.keep_last > 0) {
    try {
      const pruned = db.pruneScheduleScans(schedule.id, schedule.keep_last);
      if (pruned > 0) {
        console.log(
          `[scheduler] schedule ${schedule.id}: pruned ${pruned} old scan(s) (keep_last=${schedule.keep_last})`,
        );
      }
    } catch (e) {
      console.error(`[scheduler] schedule ${schedule.id}: prune failed: ${e.message}`);
    }
  }
  purgeAckedAlerts();
  notifier
    .dispatch("scan_done", { schedule, scan: result.scan })
    .catch((e) => console.error(`[scheduler] notify scan_done failed: ${e.message}`));
  return { status: "done", scanId: result.scanId, scan: result.scan };
}

function clearTasks() {
  for (const task of tasks.values()) {
    try {
      task.stop();
    } catch {
      // node-cron stop is idempotent; swallow.
    }
  }
  tasks.clear();
  if (digestTask) {
    try {
      digestTask.stop();
    } catch {
      // idempotent
    }
    digestTask = null;
  }
}

// Register the daily-digest cron if DIGEST_CRON is set (opt-in, like
// LATENCY_ALERT_MS). Separate from the per-scan schedules: it reports, it
// doesn't scan. An invalid expression is a loud no-op, not a crash.
function registerDigest() {
  const expr = (process.env.DIGEST_CRON || "").trim();
  if (!expr) return;
  if (!cron.validate(expr)) {
    console.error(`[scheduler] DIGEST_CRON is not a valid cron expression, digest disabled: ${expr}`);
    return;
  }
  digestTask = cron.schedule(expr, () => {
    runDigest().catch((e) => console.error(`[scheduler] daily digest failed: ${e.message}`));
  });
  console.log(`[scheduler] daily digest active (DIGEST_CRON=${expr})`);
}

// Stop everything, then re-register from the DB. Cheap enough (we deal in
// dozens of schedules at most) that we don't bother diffing.
function reload() {
  clearTasks();
  const schedules = db.listEnabledSchedules();
  for (const sched of schedules) {
    if (!cron.validate(sched.cron_expr)) {
      console.error(`[scheduler] schedule ${sched.id} has invalid cron_expr, skipping`);
      continue;
    }
    const task = cron.schedule(sched.cron_expr, () => {
      // Re-fetch in case the row was deleted/disabled between ticks.
      const current = db.getSchedule(sched.id);
      if (!current || !current.enabled) return;
      runScheduled(current).catch((e) => {
        console.error(`[scheduler] schedule ${sched.id} crashed:`, e);
      });
    });
    tasks.set(sched.id, task);
  }
  registerDigest();
  console.log(`[scheduler] ${tasks.size} schedule(s) active`);
}

// v1.17.0 — alert retention (ALERT_RETENTION_DAYS, opt-in): acknowledged
// alerts age out N days after they were acked. Global on purpose, unlike
// scan retention's per-schedule knob — an acked alert is closed bookkeeping
// wherever it came from; pending alerts are untouchable by construction.
// Runs at boot and after every completed scheduled scan; same failure rule
// as scan retention — a purge failure never taints anything, log and go on.
function purgeAckedAlerts() {
  const days = alerts.alertRetentionDays();
  if (!days) return 0;
  try {
    const purged = db.pruneAckedAlerts(Date.now() - days * 24 * 60 * 60 * 1000);
    if (purged > 0) {
      console.log(
        `[scheduler] purged ${purged} acknowledged alert(s) older than ${days} day(s)`,
      );
    }
    return purged;
  } catch (e) {
    console.error(`[scheduler] alert purge failed: ${e.message}`);
    return 0;
  }
}

function init() {
  // DEMO_MODE: the HTTP middleware blocks user-facing scan triggers, but the
  // cron timer would happily run nmap against whatever network the demo
  // container is sitting on. Don't register any tasks — the seeded schedules
  // are visual fixtures, not live jobs. (This also skips the boot purge:
  // the seeded demo alerts are fixtures, not history to age out.)
  if (process.env.DEMO_MODE === "true") {
    console.log("[scheduler] DEMO_MODE — schedules loaded as fixtures, no ticks scheduled.");
    return;
  }
  // Boot-time purge, so a manual-scans-only install still ages alerts out
  // instead of waiting for a scheduled run that never comes.
  purgeAckedAlerts();
  reload();
}

function stop() {
  clearTasks();
}

function activeIds() {
  return Array.from(tasks.keys());
}

module.exports = {
  init,
  reload,
  stop,
  runScheduled,
  runDigest,
  purgeAckedAlerts,
  validateScheduleScanOptions,
  activeIds,
};
