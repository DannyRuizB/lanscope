// v1.57.0 — a backup that holds the data, taken while LanScope runs.
//
//   docker exec lanscope node src/backup.js > lanscope-$(date +%F).db
//   docker exec lanscope node src/backup.js --check
//
// SQLite runs in WAL mode, so between checkpoints the newest rows — on a young
// install, the schema itself — live in lanscope.db-wal, not in lanscope.db.
// Copying lanscope.db alone, as the FAQ said to up to 1.56.0, gave a file with
// no tables at all (measured, with the server running and after a stop). This
// takes the snapshot through SQLite instead: VACUUM INTO writes the database
// as one reader sees it, write-ahead log included, out to a standalone file;
// the copy is integrity-checked and then streamed to stdout.
//
// The connection is read-only on purpose: `docker exec` runs as root, and a
// read-only reader never checkpoints and creates nothing in the data
// directory, so no root-owned file is left behind for the `node` server.
// Nor does this require ./db: that module opens the database read-write and
// migrates it.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const Database = require("better-sqlite3");

// Same default as src/db.js.
function defaultDbPath() {
  return process.env.DB_PATH || path.join(__dirname, "..", "data", "lanscope.db");
}

// The tables a person would miss first; counted to make the summary line
// say something a human can compare with the UI.
const COUNTED = ["scans", "hosts", "host_labels", "scheduled_scans", "alerts"];

function openReadOnly(file) {
  return new Database(file, { readonly: true, fileMustExist: true });
}

function countRows(conn) {
  const counts = {};
  const exists = conn.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?");
  for (const table of COUNTED) {
    counts[table] = exists.get(table)
      ? conn.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n
      : null;
  }
  return counts;
}

// integrity_check of a database file, plus the row counts above.
function check(file) {
  const conn = openReadOnly(file);
  try {
    const result = conn.pragma("integrity_check", { simple: true });
    return { ok: result === "ok", result, counts: countRows(conn) };
  } finally {
    conn.close();
  }
}

// Consistent copy of the database at `src` into `dest`, which must not exist
// yet (SQLite refuses to VACUUM INTO a file that has content).
function snapshot(src, dest) {
  const conn = openReadOnly(src);
  try {
    conn.prepare("VACUUM INTO ?").run(dest);
  } finally {
    conn.close();
  }
  return check(dest);
}

function describe(counts) {
  const parts = COUNTED.filter((t) => counts[t] !== null).map((t) => `${counts[t]} ${t}`);
  return parts.length ? parts.join(", ") : "no LanScope tables";
}

const USAGE = [
  "usage: node src/backup.js > lanscope-$(date +%F).db   consistent copy of the live database to stdout",
  "       node src/backup.js --check                     integrity check of the live database",
  "The database is DB_PATH (default data/lanscope.db).",
].join("\n");

async function main(args) {
  const dbPath = defaultDbPath();
  if (args.length === 1 && args[0] === "--check") {
    const r = check(dbPath);
    console.log(`${dbPath}: integrity ${r.result}; ${describe(r.counts)}`);
    return r.ok ? 0 : 1;
  }
  if (args.length > 0) {
    console.error(USAGE);
    return 2;
  }
  if (process.stdout.isTTY) {
    console.error("lanscope backup: stdout is a terminal; redirect it to a file:\n" +
      "  docker exec lanscope node src/backup.js > lanscope-$(date +%F).db");
    return 2;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lanscope-backup-"));
  try {
    const copy = path.join(dir, "lanscope.db");
    const r = snapshot(dbPath, copy);
    if (!r.ok) {
      console.error(`lanscope backup: the copy failed integrity_check (${r.result}); nothing written`);
      return 1;
    }
    const bytes = fs.statSync(copy).size;
    await pipeline(fs.createReadStream(copy), process.stdout, { end: false });
    console.error(`lanscope backup: ${bytes} bytes from ${dbPath}, integrity ok; ${describe(r.counts)}`);
    return 0;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (e) => {
      console.error(`lanscope backup: ${e.message}`);
      process.exitCode = 1;
    },
  );
}

module.exports = { snapshot, check, defaultDbPath };
