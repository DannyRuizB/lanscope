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
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip        TEXT    NOT NULL,
    mac       TEXT,
    vendor    TEXT,
    hostname  TEXT,
    status    TEXT    NOT NULL CHECK (status IN ('up','down')),
    reason    TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
  CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
`);

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
    `SELECT id, ip, mac, vendor, hostname, status, reason
       FROM hosts WHERE scan_id = ? ORDER BY ip`,
  ),
  deleteScan: db.prepare(`DELETE FROM scans WHERE id = ?`),
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
  scan.hosts = stmts.getHostsByScan.all(id);
  return scan;
}

function deleteScan(id) {
  return stmts.deleteScan.run(id).changes > 0;
}

module.exports = {
  startScan,
  finishScan,
  failScan,
  listScans,
  getScan,
  deleteScan,
};
