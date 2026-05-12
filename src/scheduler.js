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
const { validateDiscovery } = require("./scanner");
const { executeCidrScan } = require("./runner");

const tasks = new Map(); // schedule.id -> cron task

// Same shape as validateDiscovery() exposes, but scoped to the persisted
// `scan_options` blob. Today only `discovery` is honoured. Lives here so
// server.js (HTTP) and scheduler ticks share one validator.
function validateScheduleScanOptions(opts) {
  if (opts == null) return { args: [] };
  if (typeof opts !== "object" || Array.isArray(opts)) {
    return { error: "scan_options must be an object" };
  }
  if (Object.prototype.hasOwnProperty.call(opts, "discovery")) {
    const disc = validateDiscovery(opts.discovery);
    if (disc.error) return { error: `discovery: ${disc.error}` };
    return { args: disc.args };
  }
  return { args: [] };
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
    scheduleId: schedule.id,
  });

  if (result.busy) {
    db.recordScheduleRun(schedule.id, {
      status: "skipped",
      error: "another scan in progress",
    });
    return { status: "skipped", error: "another scan in progress" };
  }
  if (result.error) {
    db.recordScheduleRun(schedule.id, {
      scan_id: result.scanId,
      status: "error",
      error: result.error,
    });
    return { status: "error", scanId: result.scanId, error: result.error };
  }
  db.recordScheduleRun(schedule.id, {
    scan_id: result.scanId,
    status: "done",
  });
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
  console.log(`[scheduler] ${tasks.size} schedule(s) active`);
}

function init() {
  // DEMO_MODE: the HTTP middleware blocks user-facing scan triggers, but the
  // cron timer would happily run nmap against whatever network the demo
  // container is sitting on. Don't register any tasks — the seeded schedules
  // are visual fixtures, not live jobs.
  if (process.env.DEMO_MODE === "true") {
    console.log("[scheduler] DEMO_MODE — schedules loaded as fixtures, no ticks scheduled.");
    return;
  }
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
  validateScheduleScanOptions,
  activeIds,
};
