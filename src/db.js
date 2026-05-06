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

  CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
  CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_ports_host ON host_ports(host_id);
  CREATE INDEX IF NOT EXISTS idx_os_matches_host ON host_os_matches(host_id);
  CREATE INDEX IF NOT EXISTS idx_scripts_host ON host_scripts(host_id);
  CREATE INDEX IF NOT EXISTS idx_scripts_port ON host_scripts(host_port_id);
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
};
