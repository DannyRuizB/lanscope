"use strict";

// Prometheus text exposition (version 0.0.4), hand-rolled — the format is
// four line shapes and a client library would weigh more than this file.
//
// Everything here is a GAUGE on purpose: these numbers come out of a
// database with retention pruning (per-schedule `keep_last`, global
// ALERT_RETENTION_DAYS), so every one of them can go DOWN — and a
// Prometheus counter promises monotonicity this data cannot keep. A
// scraper that wants rates can still take deltas; lying about the type so
// the suffix looks conventional would corrupt them.

function escapeLabelValue(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n");
}

// One metric family: HELP + TYPE once, then a line per series. A family
// with zero series still gets its header lines — "known but empty" scrapes
// cleanly, and dashboards keep the metric name to hang queries on.
function gauge(lines, name, help, series) {
  lines.push(`# HELP ${name} ${help}`);
  lines.push(`# TYPE ${name} gauge`);
  for (const { labels, value } of series) {
    const rendered = labels
      ? "{" +
        Object.entries(labels)
          .map(([k, v]) => `${k}="${escapeLabelValue(v)}"`)
          .join(",") +
        "}"
      : "";
    lines.push(`${name}${rendered} ${value}`);
  }
}

// snapshot comes from db.getMetricsSnapshot(); alertTypes is db.ALERT_TYPES.
// Pending alerts are zero-filled over the full type list here: a type with
// no pending alerts is a fact worth a series ("0"), not a missing metric —
// absence would make `absent()`-style alerting and dashboards guess.
function buildMetrics(snapshot, { version, alertTypes }) {
  const lines = [];
  const nets = snapshot.networks;

  gauge(lines, "lanscope_info", "Build information.", [
    { labels: { version }, value: 1 },
  ]);
  gauge(
    lines,
    "lanscope_scans_stored",
    "Scans currently stored (retention pruning can shrink this).",
    [{ value: snapshot.scansStored }],
  );
  gauge(lines, "lanscope_scans_running", "Scans running right now.", [
    { value: snapshot.scansRunning },
  ]);
  gauge(
    lines,
    "lanscope_hosts_up",
    "Hosts up in the latest finished scan of the network.",
    nets.map((n) => ({ labels: { cidr: n.cidr }, value: n.hostsUp })),
  );
  gauge(
    lines,
    "lanscope_hosts_total",
    "Hosts seen in the latest finished scan of the network.",
    nets.map((n) => ({ labels: { cidr: n.cidr }, value: n.hostsTotal })),
  );
  gauge(
    lines,
    "lanscope_last_scan_timestamp_seconds",
    "When the latest finished scan of the network finished (unix seconds).",
    nets
      .filter((n) => n.lastScanFinishedAt != null)
      .map((n) => ({
        labels: { cidr: n.cidr },
        value: n.lastScanFinishedAt / 1000,
      })),
  );
  gauge(
    lines,
    "lanscope_last_scan_duration_seconds",
    "How long the latest finished scan of the network took.",
    nets
      .filter((n) => n.lastScanDurationMs != null)
      .map((n) => ({
        labels: { cidr: n.cidr },
        value: n.lastScanDurationMs / 1000,
      })),
  );
  gauge(
    lines,
    "lanscope_alerts_pending",
    "Unacknowledged alerts by type (every known type is always present).",
    alertTypes.map((t) => ({
      labels: { type: t },
      value: snapshot.alertsPending[t] || 0,
    })),
  );
  gauge(lines, "lanscope_schedules_enabled", "Enabled scheduled scans.", [
    { value: snapshot.schedulesEnabled },
  ]);
  gauge(lines, "lanscope_schedules_total", "Scheduled scans configured.", [
    { value: snapshot.schedulesTotal },
  ]);

  return lines.join("\n") + "\n";
}

module.exports = { buildMetrics, escapeLabelValue };
