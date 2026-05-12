// Demo fixtures (v0.9.0).
// Seeds the SQLite DB with three scans of 192.168.1.0/24 taken at different
// times so the public demo can showcase the topology graph, the diff
// (appeared / disappeared / changed) and the baseline auto-compare without
// running a real nmap. Idempotent: if the DB already has any scan, it bails.

const path = require("node:path");
const Database = require("better-sqlite3");
const db = require("./db");

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.now();

// Three scan moments, oldest first.
const T_WEEK_AGO = NOW - 7 * DAY;
const T_DAYS_AGO_3 = NOW - 3 * DAY;
const T_HOURS_AGO_4 = NOW - 4 * 60 * 60 * 1000;

const CIDR = "192.168.1.0/24";

// --- Host catalogue (the "real" devices on the LAN) ---
// Each entry is what nmap would report for that IP at its richest. We then
// snapshot a subset per scan moment to create plausible diff signals.
const ROUTER = {
  ip: "192.168.1.1",
  mac: "9C:9D:7E:11:22:33",
  vendor: "TP-LINK TECHNOLOGIES",
  hostname: "router.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Linux 4.x", accuracy: 96, line: 6700, vendor: "Linux", family: "Linux", gen: "4.X", type: "router" },
    { name: "OpenWrt 21.x", accuracy: 92, line: 6800, vendor: "OpenWrt", family: "Linux", gen: "4.X", type: "router" },
  ],
  ports: [
    { port: 22, protocol: "tcp", state: "open", state_reason: "syn-ack", service: "ssh", product: "Dropbear sshd", version: "2020.81", extra: "protocol 2.0" },
    { port: 53, protocol: "tcp", state: "open", state_reason: "syn-ack", service: "domain", product: "dnsmasq", version: "2.85" },
    { port: 80, protocol: "tcp", state: "open", state_reason: "syn-ack", service: "http", product: "lighttpd", version: "1.4.59" },
    { port: 443, protocol: "tcp", state: "open", state_reason: "syn-ack", service: "https", product: "lighttpd", version: "1.4.59" },
  ],
};

const NAS = {
  ip: "192.168.1.2",
  mac: "00:11:32:AA:BB:CC",
  vendor: "Synology Incorporated",
  hostname: "nas.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Linux 4.4 (Synology DSM 7)", accuracy: 95, vendor: "Linux", family: "Linux", gen: "4.X", type: "storage-misc" },
  ],
  ports: [
    { port: 22, protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "7.4" },
    { port: 80, protocol: "tcp", state: "open", service: "http", product: "nginx" },
    { port: 443, protocol: "tcp", state: "open", service: "https", product: "nginx" },
    { port: 5000, protocol: "tcp", state: "open", service: "http", product: "Synology DSM" },
    { port: 5001, protocol: "tcp", state: "open", service: "https", product: "Synology DSM" },
  ],
};

const WIN_DESKTOP = {
  ip: "192.168.1.10",
  mac: "B4:2E:99:DD:EE:01",
  vendor: "Intel Corporate",
  hostname: "desktop-win.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Microsoft Windows 11", accuracy: 94, vendor: "Microsoft", family: "Windows", gen: "11", type: "general purpose" },
  ],
  ports: [
    { port: 135, protocol: "tcp", state: "open", service: "msrpc", product: "Microsoft Windows RPC" },
    { port: 139, protocol: "tcp", state: "open", service: "netbios-ssn" },
    { port: 445, protocol: "tcp", state: "open", service: "microsoft-ds", product: "Microsoft Windows" },
    { port: 3389, protocol: "tcp", state: "open", service: "ms-wbt-server", product: "Microsoft Terminal Services" },
  ],
};

const LINUX_DESKTOP = {
  ip: "192.168.1.11",
  mac: "DC:A6:32:11:22:33",
  vendor: "ASUSTek COMPUTER INC.",
  hostname: "ubuntu.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Linux 6.5 (Ubuntu 24.04)", accuracy: 97, vendor: "Linux", family: "Linux", gen: "6.X", type: "general purpose" },
  ],
  ports: [
    { port: 22, protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.6p1 Ubuntu 3ubuntu13.1" },
  ],
};

const MACBOOK = {
  ip: "192.168.1.12",
  mac: "F0:18:98:AA:BB:CC",
  vendor: "Apple, Inc.",
  hostname: "danny-macbook.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Apple macOS 14.x", accuracy: 95, vendor: "Apple", family: "macOS", gen: "14.X", type: "general purpose" },
  ],
  ports: [
    { port: 5000, protocol: "tcp", state: "open", service: "rtsp", product: "AirTunes rtspd", version: "830.14.1" },
    { port: 7000, protocol: "tcp", state: "open", service: "rtsp" },
  ],
};

const PIHOLE = {
  ip: "192.168.1.20",
  mac: "DC:A6:32:55:66:77",
  vendor: "Raspberry Pi Trading Ltd",
  hostname: "pihole.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Linux 6.1 (Raspberry Pi OS)", accuracy: 96, vendor: "Linux", family: "Linux", gen: "6.X", type: "general purpose" },
  ],
  ports: [
    { port: 22, protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.2p1 Debian" },
    { port: 80, protocol: "tcp", state: "open", service: "http", product: "lighttpd", version: "1.4.69" },
    { port: 53, protocol: "tcp", state: "open", service: "domain", product: "dnsmasq", version: "2.90" },
  ],
};

const HOMEASSISTANT = {
  ip: "192.168.1.21",
  mac: "DC:A6:32:99:AA:BB",
  vendor: "Raspberry Pi Trading Ltd",
  hostname: "homeassistant.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Linux 6.6", accuracy: 95, vendor: "Linux", family: "Linux", gen: "6.X", type: "general purpose" },
  ],
  ports: [
    { port: 22, protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.6p1" },
    { port: 8123, protocol: "tcp", state: "open", service: "http", product: "Home Assistant", version: "2026.4.1" },
  ],
};

const SMART_TV = {
  ip: "192.168.1.30",
  mac: "F4:7B:5E:11:22:33",
  vendor: "Samsung Electronics",
  hostname: "samsung-tv.lan",
  status: "up",
  reason: "arp-response",
  os_matches: [
    { name: "Tizen", accuracy: 86, vendor: "Samsung", family: "Tizen", type: "media device" },
  ],
  ports: [
    { port: 8001, protocol: "tcp", state: "open", service: "http", product: "Samsung Smart TV" },
    { port: 8002, protocol: "tcp", state: "open", service: "https" },
    { port: 9197, protocol: "tcp", state: "open", service: "upnp" },
  ],
};

const CHROMECAST = {
  ip: "192.168.1.31",
  mac: "F4:F5:D8:AA:BB:CC",
  vendor: "Google, Inc.",
  hostname: "chromecast.lan",
  status: "up",
  reason: "arp-response",
  ports: [
    { port: 8008, protocol: "tcp", state: "open", service: "http", product: "Google Chromecast" },
    { port: 8009, protocol: "tcp", state: "open", service: "https" },
  ],
};

const IP_CAMERA = {
  ip: "192.168.1.40",
  mac: "EC:71:DB:11:22:33",
  vendor: "Reolink Innovation Limited",
  hostname: "camera-front.lan",
  status: "up",
  reason: "arp-response",
  ports: [
    { port: 80, protocol: "tcp", state: "open", service: "http", product: "Reolink httpd" },
    { port: 554, protocol: "tcp", state: "open", service: "rtsp" },
    { port: 9000, protocol: "tcp", state: "open", service: "cslistener" },
  ],
};

const PRINTER = {
  ip: "192.168.1.50",
  mac: "94:18:82:AA:BB:CC",
  vendor: "Hewlett Packard",
  hostname: "hp-laserjet.lan",
  status: "up",
  reason: "arp-response",
  ports: [
    { port: 80, protocol: "tcp", state: "open", service: "http", product: "HP LaserJet web admin" },
    { port: 443, protocol: "tcp", state: "open", service: "https" },
    { port: 631, protocol: "tcp", state: "open", service: "ipp", product: "CUPS" },
    { port: 9100, protocol: "tcp", state: "open", service: "jetdirect" },
  ],
};

const IPHONE = {
  ip: "192.168.1.100",
  mac: "AC:DE:48:00:11:22",
  vendor: "Apple, Inc.",
  hostname: "iphone-danny.lan",
  status: "up",
  reason: "arp-response",
};

const ANDROID_PHONE = {
  ip: "192.168.1.101",
  mac: "E8:50:8B:33:44:55",
  vendor: "Xiaomi Communications",
  hostname: "redmi-note-12.lan",
  status: "up",
  reason: "arp-response",
};

const GUEST_LAPTOP = {
  ip: "192.168.1.150",
  mac: "5C:CF:7F:99:88:77",
  vendor: "Espressif Inc.",
  hostname: null,
  status: "up",
  reason: "arp-response",
};

// --- The three scan moments ---
//
// Scan 1 (a week ago): the baseline. Most "real" devices in place,
// including the IP camera and the Android phone.
const SCAN_1_HOSTS = [
  ROUTER, NAS, WIN_DESKTOP, LINUX_DESKTOP, MACBOOK,
  PIHOLE, SMART_TV, CHROMECAST, IP_CAMERA, PRINTER,
  IPHONE, ANDROID_PHONE,
];

// Scan 2 (3 days ago): Home Assistant Pi appeared, IP camera disappeared
// (moved / unplugged), the Linux desktop got upgraded so its OS family
// detection changed slightly.
const SCAN_2_HOSTS = [
  ROUTER, NAS, WIN_DESKTOP,
  { ...LINUX_DESKTOP, os_matches: [
    { name: "Linux 6.5 (Ubuntu 24.04)", accuracy: 97, vendor: "Linux", family: "Linux", gen: "6.X", type: "general purpose" },
  ] },
  MACBOOK, PIHOLE, HOMEASSISTANT, SMART_TV, CHROMECAST, PRINTER,
  IPHONE, ANDROID_PHONE,
];

// Scan 3 (4h ago, the "current" view). Same hardware shows up, plus a guest
// laptop that connected to the LAN, and the macbook's hostname rotated via
// DHCP — flagged as "changed" against the baseline.
const SCAN_3_HOSTS = [
  ROUTER, NAS, WIN_DESKTOP,
  { ...LINUX_DESKTOP, os_matches: [
    { name: "Linux 6.5 (Ubuntu 24.04)", accuracy: 97, vendor: "Linux", family: "Linux", gen: "6.X", type: "general purpose" },
  ] },
  { ...MACBOOK, hostname: "macbook-pro-danny.lan" },
  PIHOLE, HOMEASSISTANT, SMART_TV, CHROMECAST, PRINTER,
  IPHONE, ANDROID_PHONE, GUEST_LAPTOP,
];

// --- Seed ---

function seedScan(rawDb, startedAt, hosts, durationMs = 4500) {
  const scanId = db.startScan(CIDR);
  db.finishScan(scanId, hosts);

  // Override timestamps so the demo shows realistic history.
  rawDb.prepare(`UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?`)
    .run(startedAt, startedAt + durationMs, scanId);

  // Attach OS + ports per host. The hosts inserted by finishScan are in the
  // same order as the input array, so we map by ip.
  const hostRows = rawDb.prepare(`SELECT id, ip FROM hosts WHERE scan_id = ?`).all(scanId);
  const idByIp = new Map(hostRows.map((r) => [r.ip, r.id]));
  for (const h of hosts) {
    const hostId = idByIp.get(h.ip);
    if (!hostId) continue;
    if (h.os_matches?.length) {
      db.saveHostOsMatches(hostId, h.os_matches);
      // Push osscanned_at back to the scan's started_at so the host doesn't
      // look freshly OS-scanned in the future.
      rawDb.prepare(`UPDATE hosts SET osscanned_at = ? WHERE id = ?`)
        .run(startedAt + 1000, hostId);
    }
    if (h.ports?.length) {
      db.saveHostPorts(hostId, h.ports, []);
      rawDb.prepare(`UPDATE hosts SET portscanned_at = ? WHERE id = ?`)
        .run(startedAt + 2000, hostId);
    }
  }
  return scanId;
}

// v0.10.1 — seed a few schedules so the demo shows the v0.10.0 feature in
// context (the cron timer is disabled in DEMO_MODE; these are visual fixtures).
function seedSchedules(rawDb, { scan2Id, scan2EndedAt, scan3Id, scan3EndedAt }) {
  const hourly = db.createSchedule({
    name: "Hourly home LAN sweep",
    cidr: CIDR,
    cron_expr: "0 * * * *",
    enabled: true,
    scan_options: null,
  });
  const nightly = db.createSchedule({
    name: "Nightly inventory check",
    cidr: CIDR,
    cron_expr: "0 3 * * *",
    enabled: true,
    scan_options: null,
  });
  const debug = db.createSchedule({
    name: "Aggressive watch (debug)",
    cidr: CIDR,
    cron_expr: "*/15 * * * *",
    enabled: false,
    scan_options: null,
  });

  // Backdate created_at so the rows feel like part of the seeded history,
  // not freshly created at first boot.
  rawDb.prepare(`UPDATE scheduled_scans SET created_at = ? WHERE id = ?`)
    .run(scan2EndedAt - 60 * 1000, hourly.id);
  rawDb.prepare(`UPDATE scheduled_scans SET created_at = ? WHERE id = ?`)
    .run(scan2EndedAt - 60 * 1000, nightly.id);
  rawDb.prepare(`UPDATE scheduled_scans SET created_at = ? WHERE id = ?`)
    .run(scan2EndedAt - 60 * 1000, debug.id);

  // Hourly: last successful run produced scan 3 (most recent).
  rawDb.prepare(
    `UPDATE scheduled_scans
        SET last_run_at = ?, last_scan_id = ?, last_status = 'done'
      WHERE id = ?`,
  ).run(scan3EndedAt, scan3Id, hourly.id);

  // Nightly: last successful run produced scan 2 (3 days ago).
  rawDb.prepare(
    `UPDATE scheduled_scans
        SET last_run_at = ?, last_scan_id = ?, last_status = 'done'
      WHERE id = ?`,
  ).run(scan2EndedAt, scan2Id, nightly.id);

  // Debug: last tick was skipped because the hourly job held the lock.
  rawDb.prepare(
    `UPDATE scheduled_scans
        SET last_run_at = ?, last_status = 'skipped', last_error = ?
      WHERE id = ?`,
  ).run(scan3EndedAt - 30 * 1000, "another scan in progress", debug.id);

  // Attribute the matching scans to their scheduler so History rows render
  // the ⏱ chip with the right "Scheduled by: …" tooltip.
  rawDb.prepare(`UPDATE scans SET schedule_id = ? WHERE id = ?`).run(hourly.id, scan3Id);
  rawDb.prepare(`UPDATE scans SET schedule_id = ? WHERE id = ?`).run(nightly.id, scan2Id);

  return { hourly: hourly.id, nightly: nightly.id, debug: debug.id };
}

// v0.11.0 — seed two notification channels (both disabled) so the demo shows
// the section populated without ever attempting an outbound call.
function seedChannels(rawDb, { createdAtBase }) {
  const discord = db.createChannel({
    name: "Discord home alerts",
    type: "webhook",
    config: {
      url: "https://discord.com/api/webhooks/XXXXXX/your-token-here",
      format: "discord",
    },
    events: ["scan_done", "scan_error"],
    enabled: false,
  });
  const ntfy = db.createChannel({
    name: "ntfy mobile push",
    type: "ntfy",
    config: { topic: "lanscope-demo", server: "https://ntfy.sh" },
    events: ["scan_error"],
    enabled: false,
  });

  // Backdate created_at so the rows feel like seeded fixtures.
  rawDb.prepare(`UPDATE notification_channels SET created_at = ? WHERE id = ?`)
    .run(createdAtBase, discord.id);
  rawDb.prepare(`UPDATE notification_channels SET created_at = ? WHERE id = ?`)
    .run(createdAtBase, ntfy.id);

  return { discord: discord.id, ntfy: ntfy.id };
}

function run() {
  const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "data", "lanscope.db");
  const rawDb = new Database(DB_PATH);
  const existing = rawDb.prepare(`SELECT COUNT(*) AS c FROM scans`).get().c;
  if (existing > 0) {
    console.log(`[seed] DB already has ${existing} scan(s), skipping demo fixtures.`);
    rawDb.close();
    return;
  }

  console.log(`[seed] Seeding three demo scans of ${CIDR}...`);
  const scan1 = seedScan(rawDb, T_WEEK_AGO, SCAN_1_HOSTS, 4200);
  const scan2 = seedScan(rawDb, T_DAYS_AGO_3, SCAN_2_HOSTS, 4700);
  const scan3 = seedScan(rawDb, T_HOURS_AGO_4, SCAN_3_HOSTS, 5100);

  // Mark scan 1 as the baseline so visitors landing on scan 3 see the
  // baseline auto-compare immediately.
  db.setBaseline(scan1);

  const schedIds = seedSchedules(rawDb, {
    scan2Id: scan2,
    scan2EndedAt: T_DAYS_AGO_3 + 4700,
    scan3Id: scan3,
    scan3EndedAt: T_HOURS_AGO_4 + 5100,
  });

  const chanIds = seedChannels(rawDb, {
    createdAtBase: T_DAYS_AGO_3 + 4700,
  });

  console.log(`[seed] Seeded scans: ${scan1} (baseline), ${scan2}, ${scan3}.`);
  console.log(`[seed] Seeded schedules: hourly=${schedIds.hourly}, nightly=${schedIds.nightly}, debug=${schedIds.debug}.`);
  console.log(`[seed] Seeded channels: discord=${chanIds.discord}, ntfy=${chanIds.ntfy}.`);
  rawDb.close();
}

module.exports = { run };

// CLI: `node src/seed.js`
if (require.main === module) {
  run();
}
