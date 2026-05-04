# LanScope

> Visual LAN scanner for your home network or homelab — point it at a CIDR, see who's there.

![LanScope on the dark + terminal-green theme: a 192.168.1.0/29 scan result with all four hosts port-scanned. 192.168.1.1 (Sagemcom router) shows one open port (80/tcp tcpwrapped) and five closed. 192.168.1.2 (Huawei _gateway) shows two open ports (53/tcp domain, 80/tcp http) plus three filtered (21/22/23). 192.168.1.3 (a MikroTik RouterOS box) shows six open ports with detected products: FTP "MikroTik router ftpd 7.16", SSH "MikroTik RouterOS sshd", telnet "Linux telnetd", HTTP, PPTP and "MikroTik bandwidth-test server". 192.168.1.5 (D-Link) shows one open port (80/tcp http). State pills are green for open, amber for filtered and gray for closed.](screenshots/screenshot.png)

🚧 Work in progress — v0.2.0.

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

### Port scan (v0.2)

Each host row has a **Scan ports** button in the *Ports* column. Click it and LanScope runs `nmap --top-ports 100 -sS -sV` against that single host. Results appear in an expandable sub-table showing `port/protocol`, state (open / closed / filtered, color-coded), service name, product and version when nmap can detect them.

Once a host has been port-scanned the button changes to `N open · ▾` and toggles the sub-panel open / closed without re-scanning. Port results are persisted in the database with the host, so they survive a restart.

### How it works under the hood

- The container runs a small Express server on port `3030`.
- `POST /api/scan` shells out to `nmap -sn -T4 -oX - <cidr>`. Output is XML, parsed in JavaScript with `fast-xml-parser`.
- `POST /api/hosts/:id/portscan` shells out to `nmap --top-ports 100 -sS -sV -T4 --version-light -oX - <ip>` and persists the result.
- Hosts and ports are stored in a SQLite database mounted on a Docker named volume (`lanscope-data`), so scan history survives restarts.
- The compose file uses `network_mode: host` and adds the `NET_RAW` and `NET_ADMIN` capabilities to the container — without those, `nmap` can't open the raw sockets the scans need.

### Caveats

- **Linux only.** `network_mode: host` doesn't behave the same on Docker Desktop for macOS / Windows: the container would only see Docker's internal network, not your real LAN.
- **Same subnet.** LanScope scans whatever subnet the host machine can reach. To scan a remote network you'd need a VPN or to run LanScope on a host inside that network.
- **Not a security scanner.** No exploit detection, no CVE matching. If you need that, use Nessus, OpenVAS or similar.

## Roadmap

- [x] **v0.1** — CIDR ping sweep. Web UI with a "Scan now" form, results table (IP, MAC, vendor, hostname). Persisted scan history in SQLite.
- [x] **v0.2** — Per-host TCP port scan (top 100 ports) with detected service names, products and versions. Expandable sub-table per host, results persisted alongside the host.
- [ ] **v0.3** — OS fingerprint (`nmap -O`) and host icons by OS family.
- [ ] **v0.4** — Topology graph (Cytoscape) — hosts grouped by subnet, edges via gateway.
- [ ] **v0.5** — Diff between scans: which hosts appeared / disappeared / changed since last time.
- [ ] **v0.6** — Inventory: declare which hosts *should* be on your network and get alerted when an unknown one shows up (or a known one goes missing).

## Stack

- **Backend**: Node.js 20 + Express + `better-sqlite3`.
- **Frontend**: vanilla HTML / CSS / JS, no build step.
- **Scanner**: shells out to `nmap` and parses the XML output.
- **Distribution**: Docker image built from `node:20-alpine` plus the Alpine `nmap` package.

## License

MIT © Danny Ruiz Boluda
