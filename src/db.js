const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "data", "lanscope.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr          TEXT    NOT NULL,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER,
    status        TEXT    NOT NULL CHECK (status IN ('running','done','error')),
    error_message TEXT,
    host_count    INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip            TEXT    NOT NULL,
    mac           TEXT,
    vendor        TEXT,
    hostname      TEXT,
    status        TEXT    NOT NULL CHECK (status IN ('up','down')),
    reason        TEXT,
    portscanned_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS host_ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    protocol  TEXT    NOT NULL DEFAULT 'tcp',
    state     TEXT    NOT NULL,
    service   TEXT,
    product   TEXT,
    version   TEXT,
    extra     TEXT
  );

  CREATE TABLE IF NOT EXISTS host_os_matches (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name      TEXT    NOT NULL,
    accuracy  INTEGER NOT NULL,
    line      INTEGER,
    vendor    TEXT,
    family    TEXT,
    gen       TEXT,
    type      TEXT
  );

  CREATE TABLE IF NOT EXISTS host_scripts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    host_port_id INTEGER          REFERENCES host_ports(id) ON DELETE CASCADE,
    script_id    TEXT    NOT NULL,
    output       TEXT
  );

  CREATE TABLE IF NOT EXISTS inventory_baselines (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr      TEXT    NOT NULL UNIQUE,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    set_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scheduled_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    cidr          TEXT    NOT NULL,
    cron_expr     TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    scan_options  TEXT,
    last_run_at   INTEGER,
    last_scan_id  INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    last_status   TEXT CHECK (last_status IS NULL OR last_status IN ('done','error','skipped')),
    last_error    TEXT,
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notification_channels (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    type          TEXT    NOT NULL CHECK (type IN ('webhook','ntfy')),
    config        TEXT    NOT NULL,
    events        TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    last_sent_at  INTEGER,
    last_status   TEXT CHECK (last_status IS NULL OR last_status IN ('done','error')),
    last_error    TEXT,
    created_at    INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
  CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_ports_host ON host_ports(host_id);
  CREATE INDEX IF NOT EXISTS idx_os_matches_host ON host_os_matches(host_id);
  CREATE INDEX IF NOT EXISTS idx_scripts_host ON host_scripts(host_id);
  CREATE INDEX IF NOT EXISTS idx_scripts_port ON host_scripts(host_port_id);
  CREATE INDEX IF NOT EXISTS idx_baselines_scan ON inventory_baselines(scan_id);
  CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON scheduled_scans(enabled);
  CREATE INDEX IF NOT EXISTS idx_channels_enabled ON notification_channels(enabled);
`);

// Migration for v0.1 DBs that don't have the new columns/tables yet.
function columnExists(table, column) {
  return db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .some((c) => c.name === column);
}
if (!columnExists("hosts", "portscanned_at")) {
  db.exec(`ALTER TABLE hosts ADD COLUMN portscanned_at INTEGER`);
}
if (!columnExists("hosts", "osscanned_at")) {
  db.exec(`ALTER TABLE hosts ADD COLUMN osscanned_at INTEGER`);
}
if (!columnExists("host_ports", "state_reason")) {
  db.exec(`ALTER TABLE host_ports ADD COLUMN state_reason TEXT`);
}
if (!columnExists("hosts", "udp_portscanned_at")) {
  db.exec(`ALTER TABLE hosts ADD COLUMN udp_portscanned_at INTEGER`);
}
// v0.10.0 — origin tracking. NULL means "manual" (POST /api/scan or seed).
if (!columnExists("scans", "schedule_id")) {
  db.exec(
    `ALTER TABLE scans ADD COLUMN schedule_id INTEGER REFERENCES scheduled_scans(id) ON DELETE SET NULL`,
  );
}

const stmts = {
  insertScan: db.prepare(
    `INSERT INTO scans (cidr, started_at, status, schedule_id) VALUES (?, ?, 'running', ?) RETURNING id`,
  ),
  finishScan: db.prepare(
    `UPDATE scans SET status = 'done', finished_at = ?, host_count = ? WHERE id = ?`,
  ),
  failScan: db.prepare(
    `UPDATE scans SET status = 'error', finished_at = ?, error_message = ? WHERE id = ?`,
  ),
  insertHost: db.prepare(
    `INSERT INTO hosts (scan_id, ip, mac, vendor, hostname, status, reason)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ),
  listScans: db.prepare(
    `SELECT id, cidr, started_at, finished_at, status, error_message, host_count, schedule_id
       FROM scans ORDER BY started_at DESC LIMIT ?`,
  ),
  getScan: db.prepare(
    `SELECT id, cidr, started_at, finished_at, status, error_message, host_count, schedule_id
       FROM scans WHERE id = ?`,
  ),
  getHostsByScan: db.prepare(
    `SELECT id, ip, mac, vendor, hostname, status, reason, portscanned_at, osscanned_at, udp_portscanned_at
       FROM hosts WHERE scan_id = ? ORDER BY ip`,
  ),
  getHost: db.prepare(
    `SELECT id, scan_id, ip, mac, vendor, hostname, status, reason, portscanned_at, osscanned_at, udp_portscanned_at
       FROM hosts WHERE id = ?`,
  ),
  deleteScan: db.prepare(`DELETE FROM scans WHERE id = ?`),
  clearHostPortsByProto: db.prepare(`DELETE FROM host_ports WHERE host_id = ? AND protocol = ?`),
  insertHostPort: db.prepare(
    `INSERT INTO host_ports (host_id, port, protocol, state, state_reason, service, product, version, extra)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ),
  getTcpPortsByHost: db.prepare(
    `SELECT port, protocol, state, state_reason, service, product, version, extra
       FROM host_ports WHERE host_id = ? AND protocol = 'tcp' ORDER BY port`,
  ),
  getPortsByScan: db.prepare(
    `SELECT id, host_id, port, protocol, state, state_reason, service, product, version, extra
       FROM host_ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)
       ORDER BY host_id, protocol, port`,
  ),
  markHostPortscanned: db.prepare(
    `UPDATE hosts SET portscanned_at = ? WHERE id = ?`,
  ),
  markHostUdpPortscanned: db.prepare(
    `UPDATE hosts SET udp_portscanned_at = ? WHERE id = ?`,
  ),
  getUdpPortsByHost: db.prepare(
    `SELECT port, protocol, state, state_reason, service, product, version, extra
       FROM host_ports WHERE host_id = ? AND protocol = 'udp' ORDER BY port`,
  ),
  clearHostOsMatches: db.prepare(`DELETE FROM host_os_matches WHERE host_id = ?`),
  insertHostOsMatch: db.prepare(
    `INSERT INTO host_os_matches (host_id, name, accuracy, line, vendor, family, gen, type)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ),
  getOsMatchesByHost: db.prepare(
    `SELECT name, accuracy, line, vendor, family, gen, type
       FROM host_os_matches WHERE host_id = ? ORDER BY accuracy DESC, name`,
  ),
  getOsMatchesByScan: db.prepare(
    `SELECT host_id, name, accuracy, line, vendor, family, gen, type
       FROM host_os_matches WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)
       ORDER BY host_id, accuracy DESC, name`,
  ),
  markHostOsScanned: db.prepare(
    `UPDATE hosts SET osscanned_at = ? WHERE id = ?`,
  ),
  // NSE scripts. Two delete shapes: (a) host-level (no port) and (b) all
  // scripts attached to a TCP port. UDP scripts aren't generated yet, but
  // when they are, the same delete-by-protocol cascade via host_ports FK
  // will keep them coherent with their parent ports.
  clearHostScriptsHostLevel: db.prepare(
    `DELETE FROM host_scripts WHERE host_id = ? AND host_port_id IS NULL`,
  ),
  insertHostScript: db.prepare(
    `INSERT INTO host_scripts (host_id, host_port_id, script_id, output)
     VALUES (?, ?, ?, ?)`,
  ),
  getHostScriptsByHost: db.prepare(
    `SELECT script_id, output FROM host_scripts
       WHERE host_id = ? AND host_port_id IS NULL
       ORDER BY script_id`,
  ),
  getPortScriptsByHostPort: db.prepare(
    `SELECT script_id, output FROM host_scripts
       WHERE host_port_id = ? ORDER BY script_id`,
  ),
  getScriptsByScan: db.prepare(
    `SELECT host_id, host_port_id, script_id, output FROM host_scripts
       WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)
       ORDER BY host_id, host_port_id, script_id`,
  ),
  // v0.8.0 — inventory baselines: at most one baseline scan per CIDR.
  listBaselinesStmt: db.prepare(
    `SELECT b.id, b.cidr, b.scan_id, b.set_at, s.started_at, s.host_count
       FROM inventory_baselines b
       JOIN scans s ON s.id = b.scan_id
       ORDER BY b.set_at DESC`,
  ),
  getBaselineByCidrStmt: db.prepare(
    `SELECT b.id, b.cidr, b.scan_id, b.set_at, s.started_at, s.host_count
       FROM inventory_baselines b
       JOIN scans s ON s.id = b.scan_id
       WHERE b.cidr = ?`,
  ),
  upsertBaselineStmt: db.prepare(
    `INSERT INTO inventory_baselines (cidr, scan_id, set_at)
     VALUES (?, ?, ?)
     ON CONFLICT(cidr) DO UPDATE SET scan_id = excluded.scan_id, set_at = excluded.set_at`,
  ),
  deleteBaselineByCidrStmt: db.prepare(`DELETE FROM inventory_baselines WHERE cidr = ?`),
  // v0.10.0 — scheduled scans. scan_options stored as JSON text; parsed on read.
  listSchedulesStmt: db.prepare(
    `SELECT id, name, cidr, cron_expr, enabled, scan_options,
            last_run_at, last_scan_id, last_status, last_error, created_at
       FROM scheduled_scans ORDER BY created_at DESC`,
  ),
  listEnabledSchedulesStmt: db.prepare(
    `SELECT id, name, cidr, cron_expr, enabled, scan_options,
            last_run_at, last_scan_id, last_status, last_error, created_at
       FROM scheduled_scans WHERE enabled = 1 ORDER BY id`,
  ),
  getScheduleStmt: db.prepare(
    `SELECT id, name, cidr, cron_expr, enabled, scan_options,
            last_run_at, last_scan_id, last_status, last_error, created_at
       FROM scheduled_scans WHERE id = ?`,
  ),
  insertScheduleStmt: db.prepare(
    `INSERT INTO scheduled_scans (name, cidr, cron_expr, enabled, scan_options, created_at)
     VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
  ),
  deleteScheduleStmt: db.prepare(`DELETE FROM scheduled_scans WHERE id = ?`),
  recordScheduleRunStmt: db.prepare(
    `UPDATE scheduled_scans
        SET last_run_at = ?, last_scan_id = ?, last_status = ?, last_error = ?
      WHERE id = ?`,
  ),
  // v0.11.0 — notification channels. config and events stored as JSON.
  listChannelsStmt: db.prepare(
    `SELECT id, name, type, config, events, enabled,
            last_sent_at, last_status, last_error, created_at
       FROM notification_channels ORDER BY created_at DESC`,
  ),
  listEnabledChannelsStmt: db.prepare(
    `SELECT id, name, type, config, events, enabled,
            last_sent_at, last_status, last_error, created_at
       FROM notification_channels WHERE enabled = 1 ORDER BY id`,
  ),
  getChannelStmt: db.prepare(
    `SELECT id, name, type, config, events, enabled,
            last_sent_at, last_status, last_error, created_at
       FROM notification_channels WHERE id = ?`,
  ),
  insertChannelStmt: db.prepare(
    `INSERT INTO notification_channels (name, type, config, events, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
  ),
  deleteChannelStmt: db.prepare(`DELETE FROM notification_channels WHERE id = ?`),
  recordChannelDispatchStmt: db.prepare(
    `UPDATE notification_channels
        SET last_sent_at = ?, last_status = ?, last_error = ?
      WHERE id = ?`,
  ),
  // v0.12.0 — timeline queries.
  listScansByCidrSince: db.prepare(
    `SELECT id, started_at, finished_at, status, host_count
       FROM scans
      WHERE cidr = ? AND started_at >= ?
      ORDER BY started_at ASC`,
  ),
  countOpenPortsByScan: db.prepare(
    `SELECT COUNT(*) AS n
       FROM host_ports p
       JOIN hosts h ON h.id = p.host_id
      WHERE h.scan_id = ? AND p.state = 'open'`,
  ),
  getAliveIpsByScan: db.prepare(
    `SELECT ip FROM hosts WHERE scan_id = ? AND status = 'up'`,
  ),
};

const insertHostsTx = db.transaction((scanId, hosts) => {
  for (const h of hosts) {
    stmts.insertHost.run(
      scanId,
      h.ip,
      h.mac || null,
      h.vendor || null,
      h.hostname || null,
      h.status,
      h.reason || null,
    );
  }
});

const replaceHostPortsTx = db.transaction((hostId, ports, hostScripts) => {
  // TCP rescan is the source of truth for both ports and TCP-scoped NSE
  // output. Cascading delete on host_ports drops port-level scripts; the
  // host-level scripts have no FK to ports so we wipe them explicitly.
  // If the new scan was run without --script, both lists end up empty,
  // which is the correct state.
  stmts.clearHostPortsByProto.run(hostId, "tcp");
  stmts.clearHostScriptsHostLevel.run(hostId);
  for (const p of ports) {
    const info = stmts.insertHostPort.run(
      hostId,
      p.port,
      p.protocol || "tcp",
      p.state,
      p.state_reason || null,
      p.service || null,
      p.product || null,
      p.version || null,
      p.extra || null,
    );
    const portId = Number(info.lastInsertRowid);
    for (const s of p.scripts || []) {
      stmts.insertHostScript.run(hostId, portId, s.script_id, s.output || null);
    }
  }
  for (const s of hostScripts || []) {
    stmts.insertHostScript.run(hostId, null, s.script_id, s.output || null);
  }
  stmts.markHostPortscanned.run(Date.now(), hostId);
});

const replaceHostUdpPortsTx = db.transaction((hostId, ports) => {
  stmts.clearHostPortsByProto.run(hostId, "udp");
  for (const p of ports) {
    stmts.insertHostPort.run(
      hostId,
      p.port,
      "udp",
      p.state,
      p.state_reason || null,
      p.service || null,
      p.product || null,
      p.version || null,
      p.extra || null,
    );
  }
  stmts.markHostUdpPortscanned.run(Date.now(), hostId);
});

const replaceHostOsMatchesTx = db.transaction((hostId, matches) => {
  stmts.clearHostOsMatches.run(hostId);
  for (const m of matches) {
    stmts.insertHostOsMatch.run(
      hostId,
      m.name,
      m.accuracy,
      m.line ?? null,
      m.vendor || null,
      m.family || null,
      m.gen || null,
      m.type || null,
    );
  }
  stmts.markHostOsScanned.run(Date.now(), hostId);
});

function startScan(cidr, scheduleId = null) {
  const row = stmts.insertScan.get(cidr, Date.now(), scheduleId);
  return row.id;
}

function finishScan(scanId, hosts) {
  insertHostsTx(scanId, hosts);
  stmts.finishScan.run(Date.now(), hosts.length, scanId);
}

function failScan(scanId, message) {
  stmts.failScan.run(Date.now(), message, scanId);
}

function listScans(limit = 50) {
  return stmts.listScans.all(limit);
}

function getScan(id) {
  const scan = stmts.getScan.get(id);
  if (!scan) return null;
  const hosts = stmts.getHostsByScan.all(id);
  const tcpByHost = new Map();
  const udpByHost = new Map();
  const portByDbId = new Map(); // host_ports.id -> port object (for script attach)
  for (const row of stmts.getPortsByScan.all(id)) {
    const target = row.protocol === "udp" ? udpByHost : tcpByHost;
    if (!target.has(row.host_id)) target.set(row.host_id, []);
    const port = {
      port: row.port,
      protocol: row.protocol,
      state: row.state,
      state_reason: row.state_reason,
      service: row.service,
      product: row.product,
      version: row.version,
      extra: row.extra,
      scripts: [],
    };
    target.get(row.host_id).push(port);
    portByDbId.set(row.id, port);
  }
  const hostScriptsByHost = new Map();
  for (const row of stmts.getScriptsByScan.all(id)) {
    if (row.host_port_id == null) {
      if (!hostScriptsByHost.has(row.host_id)) hostScriptsByHost.set(row.host_id, []);
      hostScriptsByHost.get(row.host_id).push({ script_id: row.script_id, output: row.output });
      continue;
    }
    const port = portByDbId.get(row.host_port_id);
    if (port) port.scripts.push({ script_id: row.script_id, output: row.output });
  }
  const osByHost = new Map();
  for (const row of stmts.getOsMatchesByScan.all(id)) {
    if (!osByHost.has(row.host_id)) osByHost.set(row.host_id, []);
    osByHost.get(row.host_id).push({
      name: row.name,
      accuracy: row.accuracy,
      line: row.line,
      vendor: row.vendor,
      family: row.family,
      gen: row.gen,
      type: row.type,
    });
  }
  for (const h of hosts) {
    h.ports = tcpByHost.get(h.id) || [];
    h.udp_ports = udpByHost.get(h.id) || [];
    h.os_matches = osByHost.get(h.id) || [];
    h.host_scripts = hostScriptsByHost.get(h.id) || [];
  }
  scan.hosts = hosts;
  return scan;
}

function deleteScan(id) {
  return stmts.deleteScan.run(id).changes > 0;
}

function getHost(id) {
  return stmts.getHost.get(id);
}

function saveHostPorts(hostId, ports, hostScripts) {
  replaceHostPortsTx(hostId, ports, hostScripts || []);
  // Re-fetch ports along with their scripts so the response reflects exactly
  // what's stored. We get port ids via a fresh query, attach scripts to each.
  const portRows = db
    .prepare(
      `SELECT id, port, protocol, state, state_reason, service, product, version, extra
         FROM host_ports WHERE host_id = ? AND protocol = 'tcp' ORDER BY port`,
    )
    .all(hostId);
  const ports2 = portRows.map((r) => ({
    port: r.port,
    protocol: r.protocol,
    state: r.state,
    state_reason: r.state_reason,
    service: r.service,
    product: r.product,
    version: r.version,
    extra: r.extra,
    scripts: stmts.getPortScriptsByHostPort.all(r.id),
  }));
  const host_scripts = stmts.getHostScriptsByHost.all(hostId);
  return { ports: ports2, host_scripts };
}

function saveHostUdpPorts(hostId, ports) {
  replaceHostUdpPortsTx(hostId, ports);
  return stmts.getUdpPortsByHost.all(hostId);
}

function saveHostOsMatches(hostId, matches) {
  replaceHostOsMatchesTx(hostId, matches);
  return stmts.getOsMatchesByHost.all(hostId);
}

function listBaselines() {
  return stmts.listBaselinesStmt.all();
}

function getBaselineByCidr(cidr) {
  return stmts.getBaselineByCidrStmt.get(cidr) || null;
}

function setBaseline(scanId) {
  const scan = stmts.getScan.get(scanId);
  if (!scan) return null;
  stmts.upsertBaselineStmt.run(scan.cidr, scanId, Date.now());
  return stmts.getBaselineByCidrStmt.get(scan.cidr);
}

function clearBaselineByCidr(cidr) {
  return stmts.deleteBaselineByCidrStmt.run(cidr).changes > 0;
}

function parseScheduleRow(row) {
  if (!row) return null;
  let opts = null;
  if (row.scan_options) {
    try {
      opts = JSON.parse(row.scan_options);
    } catch {
      opts = null;
    }
  }
  return {
    id: row.id,
    name: row.name,
    cidr: row.cidr,
    cron_expr: row.cron_expr,
    enabled: row.enabled === 1,
    scan_options: opts,
    last_run_at: row.last_run_at,
    last_scan_id: row.last_scan_id,
    last_status: row.last_status,
    last_error: row.last_error,
    created_at: row.created_at,
  };
}

function listSchedules() {
  return stmts.listSchedulesStmt.all().map(parseScheduleRow);
}

function listEnabledSchedules() {
  return stmts.listEnabledSchedulesStmt.all().map(parseScheduleRow);
}

function getSchedule(id) {
  return parseScheduleRow(stmts.getScheduleStmt.get(id));
}

function createSchedule({ name, cidr, cron_expr, enabled = true, scan_options = null }) {
  const optsJson = scan_options ? JSON.stringify(scan_options) : null;
  const row = stmts.insertScheduleStmt.get(
    name,
    cidr,
    cron_expr,
    enabled ? 1 : 0,
    optsJson,
    Date.now(),
  );
  return getSchedule(row.id);
}

// Partial update: only the fields present in `patch` are touched. Unknown keys
// are ignored. Returns the updated row (or null if id doesn't exist).
function updateSchedule(id, patch) {
  const current = stmts.getScheduleStmt.get(id);
  if (!current) return null;
  const sets = [];
  const args = [];
  if (Object.prototype.hasOwnProperty.call(patch, "name")) {
    sets.push("name = ?");
    args.push(patch.name);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "cidr")) {
    sets.push("cidr = ?");
    args.push(patch.cidr);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "cron_expr")) {
    sets.push("cron_expr = ?");
    args.push(patch.cron_expr);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "enabled")) {
    sets.push("enabled = ?");
    args.push(patch.enabled ? 1 : 0);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "scan_options")) {
    sets.push("scan_options = ?");
    args.push(patch.scan_options ? JSON.stringify(patch.scan_options) : null);
  }
  if (sets.length === 0) return parseScheduleRow(current);
  args.push(id);
  db.prepare(`UPDATE scheduled_scans SET ${sets.join(", ")} WHERE id = ?`).run(...args);
  return getSchedule(id);
}

function deleteSchedule(id) {
  return stmts.deleteScheduleStmt.run(id).changes > 0;
}

function recordScheduleRun(id, { scan_id = null, status, error = null }) {
  stmts.recordScheduleRunStmt.run(Date.now(), scan_id, status, error, id);
  return getSchedule(id);
}

function parseChannelRow(row) {
  if (!row) return null;
  let config = null;
  let events = [];
  try {
    config = row.config ? JSON.parse(row.config) : null;
  } catch {
    config = null;
  }
  try {
    events = row.events ? JSON.parse(row.events) : [];
  } catch {
    events = [];
  }
  if (!Array.isArray(events)) events = [];
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    config,
    events,
    enabled: row.enabled === 1,
    last_sent_at: row.last_sent_at,
    last_status: row.last_status,
    last_error: row.last_error,
    created_at: row.created_at,
  };
}

function listChannels() {
  return stmts.listChannelsStmt.all().map(parseChannelRow);
}

function getChannel(id) {
  return parseChannelRow(stmts.getChannelStmt.get(id));
}

// Lookup helper for the notifier dispatcher: enabled channels whose `events`
// array contains the given event name. The filter runs in JS because we deal
// with dozens of channels at most.
function listEnabledChannelsForEvent(event) {
  return stmts.listEnabledChannelsStmt
    .all()
    .map(parseChannelRow)
    .filter((c) => c && c.events.includes(event));
}

function createChannel({ name, type, config, events, enabled = true }) {
  const row = stmts.insertChannelStmt.get(
    name,
    type,
    JSON.stringify(config ?? {}),
    JSON.stringify(events ?? []),
    enabled ? 1 : 0,
    Date.now(),
  );
  return getChannel(row.id);
}

function updateChannel(id, patch) {
  const current = stmts.getChannelStmt.get(id);
  if (!current) return null;
  const sets = [];
  const args = [];
  if (Object.prototype.hasOwnProperty.call(patch, "name")) {
    sets.push("name = ?");
    args.push(patch.name);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "type")) {
    sets.push("type = ?");
    args.push(patch.type);
  }
  if (Object.prototype.hasOwnProperty.call(patch, "config")) {
    sets.push("config = ?");
    args.push(JSON.stringify(patch.config ?? {}));
  }
  if (Object.prototype.hasOwnProperty.call(patch, "events")) {
    sets.push("events = ?");
    args.push(JSON.stringify(patch.events ?? []));
  }
  if (Object.prototype.hasOwnProperty.call(patch, "enabled")) {
    sets.push("enabled = ?");
    args.push(patch.enabled ? 1 : 0);
  }
  if (sets.length === 0) return parseChannelRow(current);
  args.push(id);
  db.prepare(`UPDATE notification_channels SET ${sets.join(", ")} WHERE id = ?`).run(...args);
  return getChannel(id);
}

function deleteChannel(id) {
  return stmts.deleteChannelStmt.run(id).changes > 0;
}

// v0.12.0 — timeline data for a CIDR. Aggregates per-scan metrics and
// (if a baseline exists for the CIDR) the appeared/disappeared diff against it.
// fromTs is an epoch-ms cutoff; pass 0 to mean "all".
function getTimeline(cidr, fromTs = 0) {
  const scans = stmts.listScansByCidrSince.all(cidr, fromTs);
  if (scans.length === 0) return { cidr, baseline: null, points: [] };

  const baseline = stmts.getBaselineByCidrStmt.get(cidr) || null;
  const baselineIps = baseline
    ? new Set(stmts.getAliveIpsByScan.all(baseline.scan_id).map((r) => r.ip))
    : null;

  const points = scans.map((s) => {
    const port_count = stmts.countOpenPortsByScan.get(s.id)?.n || 0;
    const duration_ms =
      s.finished_at && s.started_at ? Math.max(0, s.finished_at - s.started_at) : null;

    let diff = null;
    if (baselineIps && s.status === "done") {
      const scanIps = new Set(stmts.getAliveIpsByScan.all(s.id).map((r) => r.ip));
      let appeared = 0;
      let disappeared = 0;
      for (const ip of scanIps) if (!baselineIps.has(ip)) appeared++;
      for (const ip of baselineIps) if (!scanIps.has(ip)) disappeared++;
      diff = { appeared, disappeared, is_baseline: s.id === baseline.scan_id };
    }

    return {
      id: s.id,
      started_at: s.started_at,
      finished_at: s.finished_at,
      status: s.status,
      host_count: s.host_count || 0,
      port_count,
      duration_ms,
      diff,
    };
  });

  return {
    cidr,
    baseline: baseline ? { scan_id: baseline.scan_id, set_at: baseline.set_at } : null,
    points,
  };
}

function recordChannelDispatch(id, { status, error = null }) {
  stmts.recordChannelDispatchStmt.run(Date.now(), status, error, id);
  return getChannel(id);
}

module.exports = {
  startScan,
  finishScan,
  failScan,
  listScans,
  getScan,
  deleteScan,
  getHost,
  saveHostPorts,
  saveHostUdpPorts,
  saveHostOsMatches,
  listBaselines,
  getBaselineByCidr,
  setBaseline,
  clearBaselineByCidr,
  listSchedules,
  listEnabledSchedules,
  getSchedule,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  recordScheduleRun,
  listChannels,
  getChannel,
  listEnabledChannelsForEvent,
  createChannel,
  updateChannel,
  deleteChannel,
  recordChannelDispatch,
  getTimeline,
};
