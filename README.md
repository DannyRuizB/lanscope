# LanScope

> Visual LAN scanner for your home network or homelab — point it at a CIDR, see who's there.

![LanScope on the dark + terminal-green theme: a 192.168.1.0/24 scan result with two hosts expanded. 192.168.1.162 (ASUSTek MAC) is OS-fingerprinted and shows a stack of Windows matches led by "Microsoft Windows 10 1803" at 97% accuracy, then 1903, 11, 1809, 1909, Server 2019 and 20H2 with descending accuracy — its OS button reads "[W] Windows · ▾". 192.168.1.184 (danny.local) is detected as "Linux 5.0 - 6.2" at 100% accuracy with the [L] Linux chip, and its ports sub-row shows 80/tcp open running nginx 1.24.0, 3000/tcp filtered ppp, 7070/tcp open realserver. Other hosts in the table have "Scan OS" and "Scan ports" buttons ready to fire. Family chips encode OS family in a single mono letter inside a green box.](screenshots/screenshot.png)

🚧 Work in progress — v0.3.1.

---

## Why

Most LAN-scanning tools are command-line only or feel stuck in 2005. LanScope is a small web UI on top of `nmap` that lets you launch a scan, browse alive hosts, and see how the network is laid out.

It is **not** a security scanner — no exploit detection, no vulnerability database. The goal is *visibility*: who's on your network, what they expose, what changed since last time.

## Scope

- Designed for **your own LAN** (home network, homelab, small office). Scan only networks you have permission to scan.
- Runs on a Linux host with Docker. The container shares the host network so `nmap` sees your real LAN.
- All data is stored locally in SQLite. Nothing leaves the machine.

## Use it

```bash
git clone https://github.com/DannyRuizB/lanscope.git
cd lanscope
docker compose up -d
# open http://localhost:3030
```

Type a CIDR in the **Target** input (for example `192.168.1.0/24`) and hit **Scan now**. Hosts that respond to the ping sweep appear in the table with their IP, MAC, vendor (looked up from the OUI prefix by `nmap`) and reverse-DNS hostname when available. Every scan is saved in the **History** sidebar — click any past scan to reload it.

### Port scan (v0.2, refined in v0.3.1)

Each host row has a **Scan ports** button in the *Ports* column. Click it and LanScope runs `nmap --top-ports 100 -sT -sV --version-light --reason` against that single host. Using a full TCP-connect scan (`-sT`) instead of SYN means an `open` result is a *real* completed handshake — no ambiguous `filtered` middle ground. The UI reflects this with two binary states:

- 🟢 **`accessible (TCP)`** — handshake completed, something is listening on that port.
- ⚪ **`not available`** — anything else (closed, filtered, no response, refused…).

Below each pill the **technical reason** is shown in small text (`syn-ack`, `conn-refused`, `no-response`…) so you keep the underlying detail.

If nmap identifies the service as web (`http`, `https`, `http-alt`, `http-proxy`, `https-alt`…), the port number itself becomes a clickable green link that opens `http://ip:port` (or `https`) in a new tab. Non-web services stay as plain text — *accessible (TCP)* doesn't mean a browser will get a useful response, just that the port is alive.

Once a host has been port-scanned the button changes to `N accessible · ▾` and toggles the sub-panel open / closed without re-scanning. Port results are persisted in the database with the host, so they survive a restart.

### OS fingerprint (v0.3)

Each host row also has a **Scan OS** button in the *OS* column. Click it and LanScope runs `nmap -O --osscan-guess` against that single host. Results appear in their own expandable sub-table listing every candidate match nmap reports, sorted by accuracy: match name (e.g. *Linux 5.0 - 6.2*, *Microsoft Windows 10 1803*, *Motorola SURFboard 5101 cable modem*), accuracy %, OS family, vendor and device type.

The OS column shows a one-letter family **chip** so you can scan a `/24` and see the OS landscape at a glance — `[L]` Linux, `[W]` Windows, `[M]` macOS / iOS, `[B]` BSD, `[R]` router / embedded, `[U]` other Unix, `[?]` unknown. The chip in the button reflects the top match; the full ranking sits inside the sub-table.

OS sub-row and ports sub-row are independent — you can have both expanded for the same host at the same time. Both are persisted, so revisiting a scan doesn't re-run nmap.

### How it works under the hood

- The container runs a small Express server on port `3030`.
- `POST /api/scan` shells out to `nmap -sn -T4 -oX - <cidr>`. Output is XML, parsed in JavaScript with `fast-xml-parser`.
- `POST /api/hosts/:id/portscan` shells out to `nmap --top-ports 100 -sT -sV -T4 --version-light --reason -oX - <ip>` and persists the result, including each port's `state_reason` from nmap.
- `POST /api/hosts/:id/osscan` shells out to `nmap -O --osscan-guess -T4 -oX - <ip>`. Every `osmatch` reported is stored, including its first `osclass` (vendor / family / generation / device type).
- Hosts, ports and OS matches are stored in a SQLite database mounted on a Docker named volume (`lanscope-data`), so scan history survives restarts.
- The compose file uses `network_mode: host` and adds the `NET_RAW` and `NET_ADMIN` capabilities to the container — without those, `nmap` can't open the raw sockets that the ping sweep, SYN scan and OS fingerprint need.

### Caveats

- **Linux only.** `network_mode: host` doesn't behave the same on Docker Desktop for macOS / Windows: the container would only see Docker's internal network, not your real LAN.
- **Same subnet.** LanScope scans whatever subnet the host machine can reach. To scan a remote network you'd need a VPN or to run LanScope on a host inside that network.
- **Not a security scanner.** No exploit detection, no CVE matching. If you need that, use Nessus, OpenVAS or similar.

## Roadmap

LanScope's direction: cover as many `nmap` options as possible behind a visual UI, **additively** — current defaults stay one click away, advanced flags become opt-in panels.

- [x] **v0.1** — CIDR ping sweep. Web UI with a "Scan now" form, results table (IP, MAC, vendor, hostname). Persisted scan history in SQLite.
- [x] **v0.2** — Per-host TCP port scan (top 100 ports) with detected service names, products and versions. Expandable sub-table per host, results persisted alongside the host.
- [x] **v0.3** — OS fingerprint (`nmap -O --osscan-guess`). Per-host OS column with one-letter family chip, expandable sub-table with every candidate match ranked by accuracy.
- [x] **v0.3.1** — Port scan switched to full TCP connect (`-sT`) for confirmed reachability. Binary `accessible (TCP)` / `not available` pills with the underlying nmap reason in small text. Web services (`http`, `https`, …) become clickable links to `http(s)://ip:port`.
- [ ] **v0.3.x** — Configurable port scan: top-N variable, port range (`-p`), timing (`-T0..T5`), connect vs SYN toggle.
- [ ] **v0.4** — UDP scan (`-sU`) on its own slower flow.
- [ ] **v0.5** — NSE scripts: `-sC` defaults plus `--script <category>` with an allowlist (banner grabbing, vuln, safe…).
- [ ] **v0.6** — Advanced host discovery: `-Pn`, ICMP / TCP / ARP ping types.
- [ ] **v0.7+** — Topology graph (Cytoscape), diff between scans (appeared / disappeared / changed), declared-host inventory with alerts.

## Stack

- **Backend**: Node.js 20 + Express + `better-sqlite3`.
- **Frontend**: vanilla HTML / CSS / JS, no build step.
- **Scanner**: shells out to `nmap` and parses the XML output.
- **Distribution**: Docker image built from `node:20-alpine` plus the Alpine `nmap` package.

## License

MIT © Danny Ruiz Boluda
