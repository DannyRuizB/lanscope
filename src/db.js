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

  CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
  CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_ports_host ON host_ports(host_id);
  CREATE INDEX IF NOT EXISTS idx_os_matches_host ON host_os_matches(host_id);
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

const stmts = {
  insertScan: db.prepare(
    `INSERT INTO scans (cidr, started_at, status) VALUES (?, ?, 'running') RETURNING id`,
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
    `SELECT id, cidr, started_at, finished_at, status, error_message, host_count
       FROM scans ORDER BY started_at DESC LIMIT ?`,
  ),
  getScan: db.prepare(
    `SELECT id, cidr, started_at, finished_at, status, error_message, host_count
       FROM scans WHERE id = ?`,
  ),
  getHostsByScan: db.prepare(
    `SELECT id, ip, mac, vendor, hostname, status, reason, portscanned_at, osscanned_at
       FROM hosts WHERE scan_id = ? ORDER BY ip`,
  ),
  getHost: db.prepare(
    `SELECT id, scan_id, ip, mac, vendor, hostname, status, reason, portscanned_at, osscanned_at
       FROM hosts WHERE id = ?`,
  ),
  deleteScan: db.prepare(`DELETE FROM scans WHERE id = ?`),
  clearHostPorts: db.prepare(`DELETE FROM host_ports WHERE host_id = ?`),
  insertHostPort: db.prepare(
    `INSERT INTO host_ports (host_id, port, protocol, state, service, product, version, extra)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ),
  getPortsByHost: db.prepare(
    `SELECT port, protocol, state, service, product, version, extra
       FROM host_ports WHERE host_id = ? ORDER BY protocol, port`,
  ),
  getPortsByScan: db.prepare(
    `SELECT host_id, port, protocol, state, service, product, version, extra
       FROM host_ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)
       ORDER BY host_id, protocol, port`,
  ),
  markHostPortscanned: db.prepare(
    `UPDATE hosts SET portscanned_at = ? WHERE id = ?`,
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

const replaceHostPortsTx = db.transaction((hostId, ports) => {
  stmts.clearHostPorts.run(hostId);
  for (const p of ports) {
    stmts.insertHostPort.run(
      hostId,
      p.port,
      p.protocol || "tcp",
      p.state,
      p.service || null,
      p.product || null,
      p.version || null,
      p.extra || null,
    );
  }
  stmts.markHostPortscanned.run(Date.now(), hostId);
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

function startScan(cidr) {
  const row = stmts.insertScan.get(cidr, Date.now());
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
  const portsByHost = new Map();
  for (const row of stmts.getPortsByScan.all(id)) {
    if (!portsByHost.has(row.host_id)) portsByHost.set(row.host_id, []);
    portsByHost.get(row.host_id).push({
      port: row.port,
      protocol: row.protocol,
      state: row.state,
      service: row.service,
      product: row.product,
      version: row.version,
      extra: row.extra,
    });
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
    h.ports = portsByHost.get(h.id) || [];
    h.os_matches = osByHost.get(h.id) || [];
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

function saveHostPorts(hostId, ports) {
  replaceHostPortsTx(hostId, ports);
  return stmts.getPortsByHost.all(hostId);
}

function saveHostOsMatches(hostId, matches) {
  replaceHostOsMatchesTx(hostId, matches);
  return stmts.getOsMatchesByHost.all(hostId);
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
  saveHostOsMatches,
};
