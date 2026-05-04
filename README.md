# LanScope

> Visual LAN scanner for your home network or homelab — point it at a CIDR, see who's there.

🚧 Scaffold — no code yet. Roadmap below.

---

## Why

Most LAN-scanning tools are command-line only or feel stuck in 2005. LanScope is a small web UI on top of `nmap` that lets you launch a scan, browse alive hosts, and see how the network is laid out.

It is **not** a security scanner — no exploit detection, no vulnerability database. The goal is *visibility*: who's on your network, what they expose, what changed since last time.

## Scope

- Designed for **your own LAN** (home network, homelab, small office). Scan only networks you have permission to scan.
- Runs on a Linux box with `nmap` installed and access to the target network.
- All data is stored locally in SQLite. Nothing leaves the machine.

## Roadmap

- [ ] **v0.1** — CIDR ping sweep. Web UI with a "Scan now" form, results table (IP, MAC, vendor, hostname). Persisted scan history in SQLite.
- [ ] **v0.2** — Per-host TCP port scan (top 100 ports) with detected service names.
- [ ] **v0.3** — OS fingerprint (`nmap -O`) and host icons by OS family.
- [ ] **v0.4** — Topology graph (Cytoscape) — hosts grouped by subnet, edges via gateway.
- [ ] **v0.5** — Diff between scans: which hosts appeared / disappeared / changed since last time.
- [ ] **v0.6** — Inventory: declare which hosts *should* be on your network and get alerted when an unknown one shows up (or a known one goes missing).

## Stack (planned)

- **Backend**: Node.js + Express + SQLite (`better-sqlite3`).
- **Frontend**: vanilla HTML / CSS / JS. Cytoscape.js for the topology graph (from v0.4).
- **Scanner**: shells out to `nmap` (XML output, parsed in JS).

## Requirements

- Linux (the scan needs raw sockets — won't work the same on macOS / Windows).
- `nmap` installed and the binary either run as root or granted `cap_net_raw,cap_net_admin+eip` via `setcap`.
- Node.js ≥ 20.

## License

MIT © Danny Ruiz Boluda
