# LanScope

[![License: MIT](https://img.shields.io/github/license/DannyRuizB/lanscope?color=blue)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/DannyRuizB/lanscope?sort=semver&color=22c55e)](https://github.com/DannyRuizB/lanscope/releases/latest)
[![Docker image](https://img.shields.io/badge/ghcr.io-lanscope-2496ed?logo=docker&logoColor=white)](https://github.com/DannyRuizB/lanscope/pkgs/container/lanscope)
[![Live demo](https://img.shields.io/badge/demo-lanscope--demo.onrender.com-22c55e)](https://lanscope-demo.onrender.com)

> Visual LAN scanner for your home network or homelab — point it at a CIDR, see who's there.

![LanScope dashboard in dark theme: the left sidebar lists a week of /24 scans and an *Hourly home LAN sweep* schedule; the main pane shows the latest scan compared against its baseline (2 appeared, 1 disappeared, 1 changed) as a host table with vendor, hostname, a latency column with inline sparklines, detected OS and open-port counts per device](screenshots/screenshot.png)

🟢 Stable — since v1.0.0.

---

## Try the demo

A **read-only public demo** runs at **[lanscope-demo.onrender.com](https://lanscope-demo.onrender.com)** — three pre-seeded scans of a synthetic `192.168.1.0/24` so you can browse the table, the topology graph, the diff between scans and the baseline auto-compare without installing anything.

Buttons that would run `nmap` (Scan now, port / OS / UDP scans, re-scan, set baseline) reply with *Demo mode: scans disabled* on the demo deploy. To run real scans against your own LAN, [install it locally](#use-it).

> Hosted on Render's free tier, so the first hit after 15 min of inactivity wakes the container up and takes ~10–30 s to respond. Subsequent navigation is instant.

## Why

Most LAN-scanning tools are command-line only or feel stuck in 2005. LanScope is a small web UI on top of `nmap` that lets you launch a scan, browse alive hosts, and see how the network is laid out.

It is **not** a security scanner — no exploit detection, no vulnerability database. The goal is *visibility*: who's on your network, what they expose, what changed since last time.

## What this demonstrates

A practical systems-and-networking project. Skills on display:

- **Networking** — host discovery and service/port scanning with `nmap`, CIDR/subnet targeting, network topology mapping and scan-to-scan diffing.
- **Containers & deployment** — Docker with `network_mode: host` and `NET_RAW` / `NET_ADMIN` capabilities, multi-arch images (amd64/arm64) published to GHCR, `docker-compose`.
- **Backend & persistence** — a web service on top of `nmap` with scan history in SQLite and scheduled recurring sweeps.
- **Ops** — read-only public demo deployed on Render's free tier.

## Scope

- Designed for **your own LAN** (home network, homelab, small office). Scan only networks you have permission to scan.
- Runs on a Linux host with Docker. The container shares the host network so `nmap` sees your real LAN.
- All data is stored locally in SQLite. Nothing leaves the machine.

## Use it

### Requirements

- **Linux host** with the LAN you want to scan attached directly (Wi-Fi or Ethernet). LanScope uses `network_mode: host`, which on Docker Desktop for macOS / Windows would only see the Docker VM's internal network, not your real LAN. **Windows 11 22H2+** users can run LanScope via WSL2 with mirrored networking — see [Windows (via WSL2)](#windows-via-wsl2). macOS still requires a Linux VM with a bridged adapter; see the [FAQ](#faq).
- **Docker Engine + Docker Compose v2** installed. `docker --version` should print 24.x or newer.
- **A few minutes**. No build is needed — the prebuilt multi-arch image lives on GHCR (`linux/amd64` + `linux/arm64`, so Raspberry Pi 4 / 5 work out of the box).

### Quickstart (recommended)

Three steps. The whole thing fits in a terminal session.

**1. Create a directory and a `docker-compose.yml`** anywhere you like (e.g. `~/lanscope/`):

```bash
mkdir -p ~/lanscope && cd ~/lanscope
cat > docker-compose.yml <<'YAML'
services:
  lanscope:
    image: ghcr.io/dannyruizb/lanscope:1.28.0
    container_name: lanscope
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    restart: unless-stopped
    environment:
      PORT: 3030
      DB_PATH: /var/lib/lanscope/lanscope.db
    volumes:
      - lanscope-data:/var/lib/lanscope
volumes:
  lanscope-data:
YAML
```

Pin a specific version (as in the snippet above) in production so upgrades are intentional. Use `:latest` if you actively want to track the newest release.

**2. Start it**:

```bash
docker compose up -d
```

Expected output:

```
[+] Running 2/2
 ✔ Volume "lanscope_lanscope-data"  Created
 ✔ Container lanscope               Started
```

The container exposes the UI on port `3030` of the **host machine** directly (because of `network_mode: host`).

**3. Open the UI**:

```bash
xdg-open http://localhost:3030    # or just point your browser at it
```

You should land on the empty LanScope dashboard. Type a CIDR in the **Target** input (e.g. `192.168.1.0/24`) and hit **Scan now**. Hosts that respond to the ping sweep appear in the table with their IP, MAC, vendor and reverse-DNS hostname. Every scan is saved in the **History** sidebar.

### Windows (via WSL2)

LanScope runs on Windows 11 (22H2 or newer) via **WSL2 with mirrored networking** — a WSL2 distro shares the host's network adapters directly, so `nmap` inside the container sees your real LAN. Docker Desktop is *not* the right path for this even with its WSL2 backend, because it wraps containers in its own internal subnet and `network_mode: host` only exposes that. Install Docker Engine inside the WSL distro instead.

**1. Install WSL2 + Ubuntu** (in an elevated PowerShell):

```powershell
wsl --install -d Ubuntu
```

Reboot if asked, then open the Ubuntu terminal and finish first-run setup (create a user, set a password).

**2. Turn on mirrored networking.** Create `%USERPROFILE%\.wslconfig` with:

```ini
[wsl2]
networkingMode=mirrored
```

Then restart WSL from PowerShell:

```powershell
wsl --shutdown
```

The next time you open Ubuntu, run `ip a` — you should see the same adapters and IP addresses as `ipconfig /all` on Windows. If you only see `eth0` with a `172.x.x.x` address, mirrored isn't active: check that `wsl --version` reports `WSL 2.0.0` or newer and that you're on Windows 11 22H2+.

**3. Install Docker Engine inside the WSL distro** (not Docker Desktop):

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# close the WSL terminal and reopen it so the group takes effect
```

**4. Continue with the Linux quickstart above** from inside the WSL terminal: create `~/lanscope/`, drop in the `docker-compose.yml`, run `docker compose up -d`.

**5. Open the UI** from your Windows browser at `http://localhost:3030`. Mirrored networking shares localhost between Windows and WSL, so no port forwarding is needed.

Caveats specific to this path:

- Mirrored networking is a Windows 11 22H2+ feature. On older Windows there is no clean way to expose the real LAN to a container — the only fallback is a full Linux VM in Hyper-V with a bridged adapter.
- MAC addresses may be empty for some hosts depending on whether the Windows network adapter exposes ARP for that segment (typical with some Wi-Fi drivers). It's the same `nmap` limitation as on Linux past a router, just triggered by a different cause.
- Docker Desktop running alongside is fine for unrelated work — just don't use its compose integration for LanScope. Install Docker Engine inside the WSL distro and run `docker compose` from there.

### Something went wrong?

If the container starts but refuses to scan, or if `docker compose up` fails outright, jump to [Troubleshooting](#troubleshooting) — the usual suspects (capabilities, Alpine `nmap-scripts`, port conflicts, MAC empty for hosts past the router) are all there with fixes.

### Build from source

If you want to modify the code or build your own image:

```bash
git clone https://github.com/DannyRuizB/lanscope.git
cd lanscope
docker compose up -d --build
# open http://localhost:3030
```

The `--build` flag overrides the `image:` pin and builds locally from the `Dockerfile`.

### Port scan (v0.2, refined in v0.3.1)

Each host row has a **Scan ports** button in the *Ports* column. Click it and LanScope runs `nmap --top-ports 100 -sT -sV --version-light --reason` against that single host. Using a full TCP-connect scan (`-sT`) instead of SYN means an `open` result is a *real* completed handshake — no ambiguous `filtered` middle ground. The UI reflects this with two binary states:

- 🟢 **`accessible (TCP)`** — handshake completed, something is listening on that port.
- ⚪ **`not available`** — anything else (closed, filtered, no response, refused…).

Below each pill the **technical reason** is shown in small text (`syn-ack`, `conn-refused`, `no-response`…) so you keep the underlying detail.

If nmap identifies the service as web (`http`, `https`, `http-alt`, `http-proxy`, `https-alt`…), the port number itself becomes a clickable green link that opens `http://ip:port` (or `https`) in a new tab. Non-web services stay as plain text — *accessible (TCP)* doesn't mean a browser will get a useful response, just that the port is alive.

Once a host has been port-scanned the button changes to `N open · ▾` and toggles the sub-panel open / closed without re-scanning. Port results are persisted in the database with the host, so they survive a restart.

### Advanced options

A collapsible **Advanced options** panel sits below the *Scan now* form. The chosen values apply to the next port scan you trigger.

- **Port scan timing** — nmap's `-T0..T5` template, default `T4` (Aggressive). Lower values are slower and stealthier (`T0` Paranoid, `T1` Sneaky, `T2` Polite); higher values are faster but more likely to lose results on flaky networks (`T5` Insane).
- **Scan technique** — *Connect (TCP)* (default, `-sT`) completes the full TCP handshake, so an `accessible (TCP)` pill means nmap really shook hands. *SYN* (`-sS`) sends a SYN and waits for SYN-ACK without completing the handshake — faster and stealthier, but firewalls that drop SYN-ACK silently can leave ports indistinguishable from genuinely closed. The pills stay binary in both modes; the underlying nmap reason (`syn-ack`, `reset`, `conn-refused`, `no-response`…) appears in small text and is what tells the two techniques apart.
- **Ports** — pick between *Top N* (the default, runs `nmap --top-ports N` over nmap's most common TCP ports — 10 / 100 / 1000 / 5000) and *Range* (an explicit `-p` spec like `80`, `1-1024` or `22,80,443,8000-8100`). Range input is validated server-side as a strict regex before reaching nmap, with each token checked against `1 ≤ N ≤ M ≤ 65535`.
- **NSE scripts** *(v0.5)* — two checkboxes: *Default* (the same set nmap runs with `-sC`: banner grabs, `http-title`, `ssh-hostkey`, `ssl-cert` …) and *Safe* (broader — everything nmap classifies as non-intrusive). You can enable one, both or neither (default). Output appears inside the existing TCP sub-row — host-level scripts in a block above the ports table, port-level scripts in a panel directly under the row that triggered them. Other categories (`vuln`, `exploit`, `brute`, `intrusive`, `dos`) are deliberately **not exposed**: LanScope is a visibility tool, not a security scanner. Validation is allowlist-only — anything outside `{default, safe}` is rejected before reaching `execFile`.
- **Host discovery** *(v0.6)* — applies to the CIDR sweep, not the per-host scans. *Skip discovery* (`-Pn`) tells nmap to treat **every host in the CIDR as up** and run no probes — useful when ICMP and SYN are both blocked, but you'll get a row per IP whether the host is real or not. The four lower checkboxes — *ICMP echo* (`-PE`), *TCP SYN* (`-PS`), *TCP ACK* (`-PA`), *ARP* (`-PR`) — are mutually combinable: nothing checked uses nmap's defaults (echo + TCP SYN to 443 + TCP ACK to 80 + ICMP timestamp, plus ARP on local LAN); checking some restricts nmap to **only** those. `-Pn` is mutually exclusive with the per-type checks and disables them when on. Validation is allowlist-only.

### UDP scan (v0.4)

Each host row also has a **Scan UDP** button in the *UDP* column. Click it and LanScope runs `nmap -sU -sV --version-light --reason` against that single host (using whichever ports / timing you have selected in the *Advanced options* panel). Because UDP has no handshake, nmap waits on timeouts: a top-100 scan typically takes **5–15 minutes** on `-T4`, so a confirmation prompt asks before starting. The scan runs server-side with a 30-minute hard timeout.

UDP states map to a tri-state pill — different from the TCP binary, on purpose:

- 🟢 **`responsive`** — `open`. A service replied to nmap's probe (typically because `-sV` sent a service-specific payload like a DNS query, NTP request or SNMP get).
- 🟡 **`unknown`** — `open|filtered`. No response. The port may be open *or* a firewall may have dropped both the probe and any ICMP unreachable. UDP cannot tell these apart, and that ambiguity is the *normal* outcome — not noise.
- ⚪ **`closed`** / **`filtered`** — ICMP port-unreachable received (closed) or another ICMP unreachable filtered explicitly (filtered).

The TCP binary (`accessible (TCP)` / `not available`) does *not* apply here: in UDP, `open|filtered` is the dominant outcome and squashing it into "not available" would be misleading. The reason for keeping the tri-state in UDP is the same reason the binary works for TCP: present what's actually informative, hide what would only confuse.

UDP results live in their own expandable sub-row, independent from the TCP ports and OS sub-rows — all three can be open at once. The button label changes from `Scan UDP` to `N responsive · ▾` (or `N unknown · ▾` if nothing was openly responsive but at least one port was *open|filtered*).

### OS fingerprint (v0.3)

Each host row also has a **Scan OS** button in the *OS* column. Click it and LanScope runs `nmap -O --osscan-guess` against that single host. Results appear in their own expandable sub-table listing every candidate match nmap reports, sorted by accuracy: match name (e.g. *Linux 5.0 - 6.2*, *Microsoft Windows 10 1803*, *Motorola SURFboard 5101 cable modem*), accuracy %, OS family, vendor and device type.

The OS column shows a one-letter family **chip** so you can scan a `/24` and see the OS landscape at a glance — `[L]` Linux, `[W]` Windows, `[M]` macOS / iOS, `[B]` BSD, `[R]` router / embedded, `[U]` other Unix, `[?]` unknown. The chip in the button reflects the top match; the full ranking sits inside the sub-table.

OS sub-row and ports sub-row are independent — you can have both expanded for the same host at the same time. Both are persisted, so revisiting a scan doesn't re-run nmap.

### How it works under the hood

- The container runs a small Express server on port `3030`.
- `POST /api/scan` shells out to `nmap -sn -T4 [-Pn | -PE -PS -PA -PR …] -oX - <cidr>`. Output is XML, parsed in JavaScript with `fast-xml-parser`. Discovery flags are optional and validated server-side against an allowlist before reaching `execFile`.
- `POST /api/hosts/:id/portscan` shells out to `nmap (--top-ports N | -p <spec>) (-sT | -sS) -sV -T<n> --version-light --reason [--script=default,safe] -oX - <ip>` and persists the result, including each port's `state_reason` from nmap. Defaults are `--top-ports 100 -sT -T4`; ports selection, scan technique, timing and NSE script categories are all overridable via the *Advanced options* panel and validated server-side before reaching `execFile`. NSE output is parsed from `<port><script>` (port-level) and `<hostscript><script>` (host-level) and stored alongside the ports.
- `POST /api/hosts/:id/udp-portscan` shells out to `nmap (--top-ports N | -p <spec>) -sU -sV -T<n> --version-light --reason -oX - <ip>`. Reuses the same ports and timing options; scan technique does not apply (UDP-only flow). 30-minute server-side timeout to accommodate the inherent slowness of UDP scanning.
- `POST /api/hosts/:id/osscan` shells out to `nmap -O --osscan-guess -T4 -oX - <ip>`. Every `osmatch` reported is stored, including its first `osclass` (vendor / family / generation / device type).
- Hosts, ports and OS matches are stored in a SQLite database mounted on a Docker named volume (`lanscope-data`), so scan history survives restarts.
- The compose file uses `network_mode: host` and adds the `NET_RAW` and `NET_ADMIN` capabilities to the container — without those, `nmap` can't open the raw sockets that the ping sweep, SYN scan and OS fingerprint need.

### Caveats

- **Linux-first**, plus Windows via WSL2 mirrored networking (see [Windows (via WSL2)](#windows-via-wsl2)). On macOS, `network_mode: host` only exposes the Docker VM's internal network, not your real LAN — run inside a Linux VM with a bridged adapter for real scanning.
- **Same subnet.** LanScope scans whatever subnet the host machine can reach. To scan a remote network you'd need a VPN or to run LanScope on a host inside that network.
- **Not a security scanner.** No exploit detection, no CVE matching. If you need that, use Nessus, OpenVAS or similar.
- **Large port ranges with mostly-closed ports show only the interesting ones.** When more than 25 ports share the same state (e.g. `closed`), nmap collapses them into an `<extraports>` summary in its XML output and only emits individual `<port>` entries for the ones that stand out (typically `open`). LanScope currently shows just the individual ports, so a `Range` of `1-65535` against a sparsely-listening host may render as a short list. The handful of *accessible* ports you do see are still accurate.

## Roadmap

LanScope's direction: cover as many `nmap` options as possible behind a visual UI, **additively** — current defaults stay one click away, advanced flags become opt-in panels.

- [x] **v0.1** — CIDR ping sweep. Web UI with a "Scan now" form, results table (IP, MAC, vendor, hostname). Persisted scan history in SQLite.
- [x] **v0.2** — Per-host TCP port scan (top 100 ports) with detected service names, products and versions. Expandable sub-table per host, results persisted alongside the host.
- [x] **v0.3** — OS fingerprint (`nmap -O --osscan-guess`). Per-host OS column with one-letter family chip, expandable sub-table with every candidate match ranked by accuracy.
- [x] **v0.3.1** — Port scan switched to full TCP connect (`-sT`) for confirmed reachability. Binary `accessible (TCP)` / `not available` pills with the underlying nmap reason in small text. Web services (`http`, `https`, …) become clickable links to `http(s)://ip:port`.
- [x] **v0.3.2** — Collapsible **Advanced options** panel, with timing template `-T0..T5` (default `T4`) configurable per port scan.
- [x] **v0.3.3** — *Ports* selector in Advanced options: *Top N* (10 / 100 / 1000 / 5000) or explicit *Range* (`-p` spec). Strict server-side validation.
- [x] **v0.3.4** — *Scan technique* selector: *Connect* (`-sT`, default) or *SYN* (`-sS`). Binary pills preserved in both modes; underlying nmap reason carries the technique-specific detail. Closes the v0.3.x line.
- [x] **v0.4** — UDP scan (`-sU`) on its own slower flow. New *UDP* column with its own button, independent expandable sub-row, tri-state pills (*responsive* / *unknown* / *closed*) suited to UDP semantics. 30-minute server-side timeout, confirmation prompt in the UI.
- [x] **v0.5** — NSE scripts as an additive option of the TCP scan. Two checkboxes in *Advanced options*: *Default* (`-sC` set) and *Safe*. Allowlist-only — `vuln` / `exploit` / `brute` / `intrusive` / `dos` are deliberately not exposed. Output rendered inside the existing TCP sub-row: host-level scripts above the ports table, port-level scripts directly under the matching row.
- [x] **v0.6** — Advanced host discovery for the CIDR sweep. *Skip discovery* (`-Pn`) reports every host as up; per-type pings *ICMP echo* (`-PE`), *TCP SYN* (`-PS`), *TCP ACK* (`-PA`) and *ARP* (`-PR`) are mutually combinable in *Advanced options*. Allowlist-validated; default behaviour unchanged.
- [x] **v0.6.1** — UI / UX overhaul, no backend or schema changes. Light / dark theme toggle in the topbar (cream / sepia warm light, near-black neutral dark) with smooth fade between themes and persistence in `localStorage`. **Bulk scan** buttons in the results header — *Scan all ports / OS / UDP* run sequentially over every alive host that hasn't been scanned yet, with a live counter and cancellable mid-flight. **History entries deletable** with a per-entry × button and a *Clear all* action. Generic confirmation modal replaces the native `window.confirm` popup. **Port hints**: a short explanation of what client you'd need to connect appears under the port number for non-HTTP services (e.g. *SSH server — connect with an SSH client*, *RDP — Remote Desktop client*). Action-column buttons aligned to the same width via `table-layout: fixed` so the OS chip sticks to the left, label centred, dropdown arrow flush right. Sub-table headers (PORT / STATE / SERVICE …) use a distinct accent so they read separately from the main table headers.
- [x] **v0.6.2** — Browse the host list, no backend or schema changes. **Filter the results by an open port**: a numeric input (1 – 65535) next to the bulk-scan buttons plus a dropdown of the five most-open ports in the current scan with a per-port host count. Filter only appears once at least one host has been port-scanned; hosts that haven't been port-scanned are excluded with an explicit empty-state message. **Sortable columns**: click *IP* / *Vendor* / *OS* / *Ports* to sort ascending (default) or descending; *Ports* defaults to descending (most-open first). IP sort is octet-aware, OS sort buckets Windows / Linux / Apple / other, hosts without that data fall to the bottom.
- [x] **v0.7.0** — **Topology graph** ([Cytoscape.js](https://js.cytoscape.org/)). A new *Table / Graph* toggle in the results header switches between the existing table view and a topology graph that puts the detected gateway in the centre and arranges every alive host on concentric rings by relevance — closer to the centre means "more known about it" (OS fingerprint + open ports, then OS or ports, then known MAC / vendor, then plain alive). Gateway is detected heuristically as `.1` or `.254` of the CIDR; when neither responded, the graph falls back to a force-directed layout with no centre. Nodes are colour-coded by OS family (Windows / Linux / Apple / Other / Unknown) and shrink to a compact pill when there is no scan data on them. Clicking a node switches back to the table, scrolls to that host's row and flashes it. The view choice persists in `localStorage` and respects the dark / light theme toggle.
- [x] **v0.7.2** — **Re-scan from the UI**, frontend-only. A small toolbar at the top of every expanded sub-row (ports / OS / UDP) carries a *Re-scan {kind}* button plus the timestamp of the last scan; clicking it re-runs that scan with the current Advanced-options settings (timing, scan technique, ports, NSE scripts, host discovery) and atomically replaces the previous data via the existing per-host endpoints. The bulk buttons in the results header switch their label to *Re-scan all {kind} (N)* once everyone has been scanned, prompting a danger-styled confirmation modal that warns about data replacement (and adds the UDP time estimate for the UDP variant). Resolves the pre-existing UX limitation, dating back to v0.2, where the per-host buttons would only toggle the sub-row once their flag was set.
- [x] **v0.7.3** — **Diff between two scans** of the same CIDR, frontend-only. A *Compare with…* button in the results header opens a dropdown listing every previous scan of the current CIDR; picking one loads it as the base and a persistent banner reports *N appeared · N disappeared · N changed*. In the table, appeared rows tint green, changed rows tint amber with an inline badge listing which fields differ (`mac` / `hostname` / `os`), and a *Disappeared since base* section at the bottom shows ghost rows in red with strike-through IPs. In the graph, appeared / changed nodes carry a coloured border and disappeared hosts re-enter as ghost nodes with a dashed red border and reduced opacity. Switching to a scan of a different CIDR clears the comparison automatically. Diff was scoped against MAC / hostname / OS family changes only — set-of-open-ports differences are intentionally excluded to avoid noise from partial re-scans.
- [x] **v0.8.0** — **Declared inventory via baselines**. A new ★ *Set as baseline* button in the results header marks the current scan as the canonical state of its CIDR (`inventory_baselines(cidr UNIQUE, scan_id)` in the schema). When you later open any other scan of the same CIDR, LanScope automatically compares it against the baseline and shows the v0.7.3 diff (appeared / disappeared / changed) without you having to pick anything from the *Compare with…* dropdown. The diff banner switches to a yellow accent and reads *★ Compared against baseline* so you know whether the comparison is auto (against baseline) or manual (against another scan). Sidebar entries that are the baseline of their CIDR carry a ★ marker. Manual *Compare with…* picks override the baseline auto-compare for the current view; *Exit diff* turns it off until you switch to another scan; switching to another scan re-enables it.
- [x] **v0.8.1** — **Pre-built image on GHCR** (`ghcr.io/dannyruizb/lanscope`). A GitHub Action runs on every `v*` tag, builds the image for `linux/amd64` and `linux/arm64` via QEMU + buildx, and pushes both an exact-version tag (e.g. `:0.8.1`) and `:latest`. `docker-compose.yml` now defaults to the GHCR image so newcomers can `docker compose up -d` without cloning the repo; local development still uses `docker compose up -d --build` and that flag takes precedence over the pinned image.
- [x] **v0.8.2** — **Expanded README**: FAQ and Troubleshooting sections covering the legal angle, the macOS / Windows situation, where the data lives, how to back up and upgrade, plus fixes for the gotchas the project has accumulated (Alpine `nmap-scripts`, `cap_add` capabilities, `network_mode: host`, the restart-vs-rebuild trap, port conflicts, empty MAC fields, the `-Pn` quirk, GHCR auth, SQLite WAL files).
- [x] **v0.8.3** — **Closing polish** (no app changes): OCI image labels (`org.opencontainers.image.{title, description, source, url, documentation, licenses, authors}`) so the GHCR package page and `docker inspect` show project metadata directly; `.gitignore` covers `preview-*.html` scratch files; GitHub repo topics added for discovery.
- [x] **v0.9.0** — **Public read-only demo**. New `DEMO_MODE=true` env var: when set, an Express middleware turns the API read-only (every non-GET responds 403 with a friendly *Demo mode: scans disabled* JSON), `GET /api/config` exposes the flag to the frontend, and a `src/seed.js` script populates a fresh SQLite with three plausible scans of `192.168.1.0/24` (12 / 12 / 13 hosts across a week, baseline pinned to the oldest, diff visible from the newest). The UI surfaces a yellow *Demo · read-only* banner when the API reports demo mode. A `render.yaml` blueprint hosts the demo on Render's free tier (Frankfurt, no persistent disk — DB is re-seeded on each cold start, which is exactly what a fixture-only demo needs). The README quickstart is rewritten with explicit prerequisites and numbered steps with expected output.
- [x] **v0.10.0** — **Scheduled scans**: first step of the **Network Observability** track. A new `scheduled_scans` table (name, CIDR, cron expression, enabled flag, optional scan options, plus `last_run_at` / `last_scan_id` / `last_status` / `last_error`) and a sibling `schedule_id` column on `scans` (nullable, `ON DELETE SET NULL`) so every scan knows whether it was triggered manually or by the scheduler. REST surface: `GET /api/schedules`, `POST /api/schedules` with validation of name / CIDR / cron expression / options, `PATCH /api/schedules/:id` for partial edits, `DELETE /api/schedules/:id`, and `POST /api/schedules/:id/run-now`. A new `src/scheduler.js` module registers a [`node-cron`](https://github.com/node-cron/node-cron) task per enabled row on boot and reloads after every mutation; a new `src/runner.js` module owns a process-wide `scanInFlight` lock so the cron timer, the *Run now* button and `POST /api/scan` cannot trample each other — a colliding call returns `409 another scan is already in progress` for HTTP and records `last_status='skipped'` for a missed tick. UI: a *Schedules* section in the sidebar lists every schedule with its frequency in human form (*Every 15 minutes*, *Daily at 3:00 AM*, *Custom — …*) plus an inline *Run now* button, an *On/Off* toggle and a *×* delete. A modal *+ New* dialog offers four cron presets plus a custom input. Each schedule row shows its last run as `✓ HH:MM · N hosts`, `✗ HH:MM · error` (tooltip carries the message) or `⊘ HH:MM · skipped`. In *History*, every scan generated by a schedule carries a small *⏱* chip with a *Scheduled by: &lt;name&gt;* tooltip.
- [x] **v0.10.1** — **Demo polish**, no app changes. The Render public demo now showcases v0.10.0 in context: `src/seed.js` inserts three schedules alongside the seeded scans — *Hourly home LAN sweep* (enabled, last run = scan 3), *Nightly inventory check* (enabled, last run = scan 2) and *Aggressive watch (debug)* (disabled, last run skipped) — and back-fills `scans.schedule_id` so the History rows show the *⏱* chip with the right tooltip. `src/scheduler.js` now early-returns in `init()` when `DEMO_MODE=true`, so the seeded schedules remain visual fixtures and the cron timer never tries to run `nmap` against Render's internal network. `render.yaml` bumped to `:0.10.1`.
- [x] **v0.12.0** — **History + timeline charts**: third step of the **Network Observability** track. A new per-CIDR *Timeline* view aggregates every scan of a network into four charts side by side — *Hosts alive*, *Open ports*, *Scan duration (s)* and *Baseline diff* (appeared / disappeared vs the declared baseline). New `GET /api/timeline?cidr=…&range=24h|7d|30d|all` endpoint that returns per-scan metrics in chronological order, including the diff against the inventory baseline when one exists. No schema change — all numbers are derived from the existing `scans`, `hosts`, `host_ports` and `inventory_baselines` tables. UI: a *📈 Timeline* button in the results header opens the view full-width with a range toggle (24h / 7d / 30d / All); clicking any data point loads that exact scan. *Esc* and the *Close* button restore the previous scan view. [Chart.js](https://www.chartjs.org/) 4.4.7 loaded by CDN, no new runtime dependencies. The demo seed gains eight intermediate fixture scans between the baseline and the latest run, so the public demo on Render shows a populated timeline out of the box.
- [x] **v0.11.0** — **Notifications**: second step of the **Network Observability** track. A new `notification_channels` table (name, type `webhook`/`ntfy`, JSON config, JSON event list, enabled flag, plus `last_sent_at` / `last_status` / `last_error`) and a new `src/notifier.js` module fan out scheduled-scan events to subscribed channels. Three event types: `scan_done`, `scan_error`, `scan_skipped`. Two channel kinds: **webhook** with three payload formats — `generic` (a flat `{event, summary, schedule, scan, error}` JSON), `discord` (Discord Incoming Webhook with coloured embed) and `slack` (Slack Incoming Webhook text), and **ntfy.sh** with `Title` / `Tags` / `Priority` headers and plain-text body. The scheduler dispatches fire-and-forget after every run; a broken channel is recorded in `last_status='error'` without affecting siblings or the scan itself. Each delivery uses a 5 s `AbortSignal.timeout`. REST surface: `GET / POST / PATCH / DELETE /api/notifications` with strict validation (type allowlist, channel type is immutable in PATCH, URL must be http(s), ntfy topic is `[A-Za-z0-9_-]{1,64}`, events deduped against `{scan_done, scan_error, scan_skipped}`), plus `POST /api/notifications/:id/test` that fires a synthetic `scan_done` payload and awaits the downstream response so the UI can show the result inline (200 on success, 502 on downstream failure). UI: a *Notifications* section in the sidebar lists every channel with a type chip (`WEBHOOK` / `NTFY`), the chosen format or topic, the event list, a *✓ HH:MM* / *✗ error* last-sent badge, an inline *▶ Test* button, an *On/Off* toggle and a *×* delete. A modal *+ New* dialog switches between webhook fields (URL + format selector) and ntfy fields (topic + optional server) on the fly. In `DEMO_MODE` the dispatcher short-circuits without making any outbound calls, so the public Render demo can ship two seeded fixtures (a disabled Discord webhook and a disabled ntfy.sh channel) without risk. `package.json` declares the new feature directly on top of Node 20's built-in `fetch` — no new runtime dependencies.
- [x] **v0.13.1** — **CSS patch**: fix Chart.js timeline cards growing unbounded on every redraw. Root cause was a flex layout where the card used `min-height` instead of `height` and the canvas inherited a `min-height: 200px` — combined with `responsive: true` + `maintainAspectRatio: false` it produced a resize loop that pushed each chart taller on every render. The fix pins the card to `height: 280px` and gives the canvas `min-height: 0` so a flex child stops dragging its parent along. No JS / schema change.
- [x] **v1.0.0** — **First stable release**. Closes the Network Observability track (v0.10 scheduled scans → v0.11 notifications → v0.12 timeline → v0.13 baseline alerts). No new app features over v0.13.1 — this tag is the "everything is solid, go look at it" milestone, with the four work blocks below in place: **A) Quality gates** — GitHub Actions bumped to versions running on Node 24, a `smoke.yml` workflow probes the API and HTML on every push to `main` and every PR, `SECURITY.md` brought current with the v0.13 scope. **B) Marketing surface** — README has badges (license, latest release, GHCR, demo) at the top, the topology screenshot stays as the hero. **C) Distribution drafts** — an awesome-selfhosted YAML entry queued for 2026-09 submission (their 4-month rule), Show HN draft and Reddit drafts for r/selfhosted + r/homelab ready in `drafts/`. **D) UX polish** — empty-state copy unified across the four sidebar sections plus alerts, tooltip + `aria-label` audit closing the gaps left by the v0.13 sidebar entry / rescan toolbar / alert chips, WCAG AA contrast bump on alert chips (Tailwind 700-range), `button:focus-visible` ring restored for keyboard navigation, `role=status` + `aria-live=polite` on the scan-progress banner. **Internal cleanup**: an agent-driven simplify pass on the v0.13 code reused `fmtTime` / `validateCidr` / `db.ALERT_TYPES`, collapsed seven event helpers in the notifier into one `EVENT_META` table, batched alert inserts inside a single `db.transaction`, cached the badge count for early-return on no-op polls, and gated the 30 s polling timer on `visibilitychange` so hidden tabs stop fetching.
- [x] **v0.13.0** — **Baseline alerts**: fourth step of the **Network Observability** track. A new `alerts(scan_id, host_id, cidr, type, payload JSON, created_at, acknowledged_at)` table and a new `src/alerts.js` module detect six divergence events after every successful scan — `appeared`, `disappeared`, `changed_mac`, `changed_hostname`, `changed_os` (by family bucket, not raw nmap accuracy — `windows` / `linux` / `apple` / `other`), `changed_ports` (TCP open-port set diff). Matching is by IP. Detection runs only when the CIDR has a declared inventory baseline; without one no alerts are generated, by design. Anti-noise guards: MAC and hostname require both ends non-null (one scan missing a value is not "changed"), OS and ports require both hosts scanned, UDP ports are intentionally excluded. REST surface: `GET /api/alerts?cidr=…&unackOnly=true&types=appeared,changed_mac&limit=…`, `GET /api/alerts/count` (drives the sidebar badge), `POST /api/alerts/:id/ack`, `DELETE /api/alerts/:id`. A new `baseline_diff` event is added to the notifier (v0.11.0): one aggregated dispatch per scan with `{total, counts, baseline}` fields in the generic webhook payload, an orange `⚠` Discord embed, the same summary line on Slack and ntfy.sh (`Priority: high`). The event is opt-in per channel via a fourth checkbox in the *New channel* modal. UI: a new *Alerts* entry in the sidebar with a red unack-count badge (hidden when zero) opens a modal with a *Unacknowledged / All* scope toggle and per-type checkboxes; rows carry a colour-coded type chip (green appeared, red disappeared, amber changed), a one-line change description, a clickable *scan #N* link that loads that scan, an *acked* tag when applicable, and inline *✓ Ack* / *×* delete buttons. The badge refreshes at boot, after every history change (new scan, delete, clear), after every ack / delete, and on a 30 s polling timer so cron-driven scans don't leave a stale counter while the tab is open. The demo seed adds six alerts derived from the real detector against the seeded scan 2 (two, acked, simulating prior triage) and scan 3 (four, pending, ready to act on), so the public demo on Render lands with a populated badge out of the box.
- [x] **v1.1.0** — **Export scans as CSV / JSON**. New `GET /api/scans/:id/export?format=csv|json` endpoint — a GET on purpose, so it also works on the read-only public demo and the browser can download it with a plain anchor click. The CSV (new `src/export.js` module, unit-tested) is one row per host with flat columns (`ip, mac, vendor, hostname, status, os, os_accuracy, tcp_open_ports, tcp_services, udp_open_ports`): RFC 4180 escaping with CRLF line endings, a UTF-8 BOM so Excel / LibreOffice detect the encoding, only `open` TCP ports and only `open` UDP ports (the same criterion as the UI's *responsive* pill — `open|filtered` is a shrug, not an inventory fact), and services rendered as `port/name (product version)`. The JSON variant is the full scan object exactly as served by the API (hosts, ports, scripts, OS matches). UI: a *⬇ Export* dropdown in the results header, visible whenever a scan is loaded, offering *CSV — hosts table* and *JSON — full scan*; the `Content-Disposition` filename is `lanscope_scan-<id>_<sanitized-cidr>.<format>`.
- [x] **v1.2.0** — **Wake-on-LAN**. A `⏻` button in the MAC column — on live rows and, more usefully, on the *Disappeared since base scan* rows, where "this device went missing, bring it back" is the whole point. New `src/wol.js` module (zero new dependencies, `node:dgram`): builds the 102-byte magic packet (6×`0xFF` + MAC ×16, unit-tested byte by byte, delivery tested over a loopback UDP listener) and broadcasts it to `255.255.255.255:9`. New `POST /api/hosts/:id/wake` — unlike the scan endpoints it doesn't require the host to be *up* (waking a sleeping device is the point), but it does require a captured MAC: the packet is addressed to the NIC, not the IP. The button reports `✓ sent` / `✗` inline; WOL is fire-and-forget — nothing acks a broadcast — so whether the device actually woke shows up in the next scan. See the FAQ for the requirements.
- [x] **v1.3.0** — **Host labels & notes**. An ✎ button in the hostname cell opens a small modal with a *Friendly name* (max 64 chars) and *Notes* (max 500): "which of these 14 IPs is the printer?" finally has an answer that survives re-scans. Labels live in a new `host_labels(cidr, ip, label, notes)` table keyed by **(network, IP)** — not by scan — so they follow the device across every scan of that CIDR, past and future, including the ghost rows of the diff view. Shown as an accent-colored name above the real hostname in the table, as the first line of the node label in the topology graph, and as a new `label` column in the CSV export; notes surface as a 🗒 chip with a tooltip. REST: `GET /api/labels?cidr=…` and an idempotent `PUT /api/labels` (validated: CIDR, IPv4, length caps; clearing both fields removes the row — an absent label, not an empty string to drag around). The public demo ships three seeded labels; editing is blocked there by `DEMO_MODE` like every other mutation. Footer version had been stuck at v0.12.0 since the timeline release — fixed.
- [x] **v1.4.0** — **Latency column**. nmap already measures every host's smoothed round-trip time (`<times srtt=…>` in the XML, microseconds) and LanScope was throwing it away. Now parsed (`latency_ms`, one decimal — 0.4 ms wired vs 45 ms on a flaky Wi-Fi repeater is the whole story), stored (`hosts.latency_ms REAL` + migration for old DBs), shown as a new sortable *Latency* column (ascending by default; unmeasured hosts fall to the bottom) and exported as a `latency_ms` CSV column. Null when nmap didn't time the host (e.g. `-Pn` without probes). The demo seed carries per-device latencies so the public demo shows the wired/wireless split out of the box.
- [x] **v1.5.0** — **Latency in the Timeline**. The per-host latency from v1.4 aggregated over time: every `/api/timeline` point now carries `avg_latency_ms` — the average of the scan's measured host latencies (SQL `AVG`, one decimal, `null` when no host in that scan was timed) — and the Timeline view gains a fifth chart, *Avg latency (ms)*, next to hosts / ports / duration / baseline diff. A rising line there is the network itself degrading (Wi-Fi congestion, a flaky switch), which no host count or port diff would ever show. Scans without a measurement render as a gap (`spanGaps`), not a fake zero. No schema change — the number is derived from the existing `hosts.latency_ms` column.
- [x] **v1.6.0** — **Optional HTTP Basic Auth**. LanScope's UI can start a scan against whatever network the container reaches, and the inventory it shows is itself sensitive — an instance exposed beyond localhost deserves a lock. Set **both** `AUTH_USER` and `AUTH_PASS` and every request (static UI *and* API — the UI leaks the whole inventory, not just the mutating endpoints) requires the credential; the default stays open for the localhost / homelab case and the public demo. New `src/auth.js` module, unit-tested: constant-time comparison (sha256 digests + `crypto.timingSafeEqual`, both user and password always compared so a wrong username costs the same as a wrong password), passwords may contain `:` (only the first colon separates), `401` with a proper `WWW-Authenticate` challenge so browsers pop their native prompt. Half-configured (one variable without the other) **refuses to start** — a lock silently left open is the worst outcome. Commented-out `AUTH_USER` / `AUTH_PASS` lines ship in `docker-compose.yml`; pair with TLS via reverse proxy, as the SECURITY.md note explains.
- [x] **v1.7.0** — **Per-host history**: fifth step of the **Network Observability** track — the timeline answered "how is the *network* doing?", this answers "how is *this device* doing?". A new 📈 button next to every host's label button opens a modal with the host's trajectory across **every scan of its CIDR**: a latency line chart (Chart.js, gaps — never fake zeros — when a scan didn't time the host, point colour = presence: green up, red down, grey not seen) over a compact table (scan, date, state, latency, open TCP count). New `GET /api/host-history?cidr=…&ip=…` — a GET on purpose, so it works on the read-only demo. The series keeps a slot for scans where the host was absent (`present: false` — the *hole* is the story when a device disappears), and `tcp_open_ports` stays `null` for scans that never port-scanned the host: "not scanned" and "zero ports open" are different facts. No schema change — derived from `scans` × `hosts` × `host_ports`.
- [x] **v1.8.0** — **Scan retention**: sixth step of the **Network Observability** track — scheduled scans made the database grow forever; now each schedule can clean up after itself. A new optional *Retention* field ("keep last N scans") on every schedule: after each successful run, that schedule's scans beyond the newest N are pruned (each deletion takes its hosts / ports / scripts along via `ON DELETE CASCADE`). Two kinds of scans are **never** pruned: the CIDR's declared ★ baseline (its `inventory_baselines` row would cascade away with it — the declared inventory must outlive any retention window) and scans that still carry **unacknowledged alerts** (retention must not silently swallow open findings; acknowledged ones are triaged and free to go). Manual scans and other schedules' scans are untouched — only the schedule's own history is windowed. `keep_last INTEGER` column (nullable — `null` keeps everything, the previous behaviour and still the default) with migration for old DBs, validated end to end (`POST` / `PATCH /api/schedules` accept `1..10000` or `null` to clear), shown as *keeps last N* in the schedule row and as a *Retention* field in the *+ New* modal. The demo's hourly schedule keeps last 24 so the feature is visible out of the box.
- [x] **v1.9.0** — **Latency sparklines**: the latency story, finished — v1.4 put the number in the table, v1.5 averaged it per scan in the Timeline, v1.7 charted one host in a modal; now every host row carries its own **inline trend**. A tiny SVG sparkline next to the latency value shows that host across the **last 20 scans of its network**, scaled to the host's own min–max (the shape — spikes, drift, flapping WiFi — is the point, not cross-host comparison). Gaps stay gaps: a scan where the host was absent or untimed splits the line instead of faking a zero, and an isolated measurement between gaps renders as a dot; fewer than two measurements render nothing (one point has no trend). Data comes from one bulk call — new `GET /api/latency-sparks?cidr=…` returns every host's series aligned on one shared scan axis (a GET on purpose: works on the read-only demo) — cached per *(network, scan)* so switching scans refreshes the trend but re-renders don't refetch. No schema change, no new dependencies: plain SVG polylines, no Chart.js in the table.
- [x] **v1.10.0** — **Host-history export + uptime%**: the 📈 modal (v1.7) grows the two things it was missing. A **⬇ CSV / ⬇ JSON** pair (same anchor-download pattern as the scan export, `GET /api/host-history/export?cidr&ip&format`, a GET so it works on the read-only demo) writes one row per scan of the host's network — *including the scans where it was absent*, so the file shows the gaps rather than a compacted history. And an **uptime chip** in the modal header: the share of the scans that actually *covered* the host where it was `up`. Absent scans are deliberately not counted — the host simply wasn't in that sweep's scope, which is not a downtime signal — so the figure answers "when this device was in range, how often was it alive?" (`null`/"no coverage" instead of a misleading 0% when nothing covered it). Computed in `getHostHistory` (`uptime: {pct, scans_up, scans_counted}`), colour-banded green/amber/red at 99 / 90.
- [x] **v1.11.0** — **Free-text host search**. A *Search hosts…* box in the results header filters the table as you type: one case-insensitive substring match over everything you'd use to look for a device — IP, MAC, vendor, hostname, its friendly label (v1.3), detected OS names and **open** port numbers (closed ports are deliberately not indexed — the same "open only" criterion as the CSV export and the port filter). A quiet *N of M* counter appears next to the box only while a query is active, and the search **composes** with the port filter instead of replacing it (search applies on top of the port-filtered set). The *Disappeared since base scan* ghosts stay visible regardless of the query, consistent with how the port filter treats them — they aren't part of the current host list. Matching lives in a new `src/public/host-search.js`: pure and DOM-free with a dual browser / node export, so the exact code the browser runs is unit-tested under `node --test`; re-render per keystroke, same pattern as the port filter (host lists are small enough that it's instant). No backend, schema or dependency changes.
- [x] **v1.12.0** — **Latency threshold alerts**: seventh step of the **Network Observability** track, and the latency story turned *actionable* — v1.4 measured it, v1.5/v1.7/v1.9 charted it, now it can page you. Set **`LATENCY_ALERT_MS`** (unset = off, the default) and every scan that times a host **at or above** the threshold raises a **`high_latency`** alert — new alert type in the v0.13 pipeline, so it lands in the same sidebar badge, modal (own indigo chip, filterable) and notifier digest as the baseline alerts. Unlike those, it deliberately **needs no baseline**: high latency is a statement about the *current* scan's health, not about divergence from a declared inventory — a fresh install with one env var gets it. Hosts the scan didn't time are skipped ("not timed" ≠ "slow", the same honesty rule as v1.7/v1.10), strict parse (zero / negatives / garbage mean *off*, never a threshold that matches everything). The `alerts.type` CHECK predates the new type and SQLite can't alter a CHECK — existing DBs get the alerts table rebuilt once, data and ids preserved. The demo sets `LATENCY_ALERT_MS=50`, above its wired devices and inside the WiFi devices' sway, so a couple of alerts show out of the box.
- [x] **v1.13.0** — **`high_latency` notifier event**: eighth step of the **Network Observability** track — the latency alerts of v1.12.0 become their own *subscribable* notification event instead of riding inside the `baseline_diff` digest. That digest mislabeled them (a slow WiFi camera is not "baseline divergence" — v1.12.0 deliberately made the detector baseline-free) and made them impossible to route separately: a latency page usually wants a different channel than an inventory-drift alarm. After every scan the runner now partitions the alerts: drift types keep firing the aggregated `baseline_diff` (its `total`/`counts` no longer inflated by latency rows), and any `high_latency` alerts fire one `high_latency` event with `{total, threshold_ms, slow_hosts}` in the generic webhook payload — `slow_hosts` capped at the 5 worst offenders (`ip`, `hostname`, `latency_ms`, sorted slowest first) so a /16 with a sick uplink doesn't turn the notification into a phone book, while `total` still says how many. Discord embed in the same indigo as the UI's alert chip, `:hourglass:` on Slack, `Priority: default` on ntfy.sh (visibility, not a pager storm). Fifth event checkbox in the channel modal (off by default, like `baseline_diff`), allowlisted in the validators, and the seeded ntfy fixture subscribes to it so the demo shows the event exists. Payload keeps the stable-shape rule: the new fields are always present and `null` on every other event.
- [x] **v1.14.0** — **Per-schedule latency threshold**: ninth step of the **Network Observability** track — `LATENCY_ALERT_MS` stops being all-or-nothing. Each schedule can now carry its own `latency_alert_ms`: **`null` inherits the global env** (the default, nothing changes on upgrade), **`0` turns latency alerts off for that schedule only** (the WiFi-heavy guest subnet stops paging without silencing everyone else), **`N > 0` is its own bar** — stricter or laxer than the global. Manual scans have no schedule and keep using the env. The per-alert `threshold_ms` payload (and therefore the `high_latency` notifier event of v1.13.0) automatically reports the bar that actually judged the scan. Nullable column, no CHECK — no table rebuild (the v1.12.0 lesson). REST: `POST`/`PATCH /api/schedules` accept the field (validated 0–600000, integers only); UI: a *Latency alert (ms)* field in the schedule modal (empty = inherit) and a *· latency ≥ N ms* / *· latency alerts off* chip on the row; the seeded nightly schedule wears one in the demo.
- [x] **v1.15.0** — **Daily digest** notifier event: tenth step of the **Network Observability** track, and the low-key counterpart to the per-event alerts. Set **`DIGEST_CRON`** (opt-in, like `LATENCY_ALERT_MS`) and once a day the scheduler fires a **`daily_digest`** event — a per-CIDR roll-up over the last `DIGEST_WINDOW_HOURS` (default 24): scans run, new alerts by type, and the pending (unacked) backlog you'd want a morning nudge about. One dispatch summarising every active network, not a page per finding: `📊` Discord embed, `:bar_chart:` on Slack, ntfy `Priority: low`. A CIDR appears only if it saw a scan or a new alert in the window — a silent network isn't noise. The generic payload carries `{window_hours, digest:{cidrs, totals}}` under the stable-shape rule (null on every other event). New sixth event checkbox in the channel modal (off by default); the seeded Discord channel subscribes to it. Its own cron, separate from the scan schedules — it reports, it doesn't scan; a bad `DIGEST_CRON` is a loud no-op, and `DEMO_MODE` skips it like every other timer.
- [x] **v1.16.0** — **Send digest now**: a `POST /api/digest/run` endpoint (and a *📊 Digest now* button in the Notifications panel) that fires the daily digest **on demand** instead of waiting for the `DIGEST_CRON` tick — same code path (`scheduler.runDigest`), so a channel subscribed to `daily_digest` gets exactly what it would at 8am. Handy to preview the digest while setting a channel up, or to trigger one from your own cron/webhook. The `DEMO_MODE` middleware already `403`s it (it's a POST) and the notifier short-circuits in demo, so the public demo stays inert. The button reports how many channels it reached (or that none are subscribed).
- [x] **v1.17.0** — **Alert retention**: the housekeeping counterpart to v1.8.0's scan retention. Set **`ALERT_RETENTION_DAYS`** (opt-in, like every other knob — unset keeps the previous keep-everything-forever behaviour) and **acknowledged** alerts age out N days **after they were acked**: the clock runs from `acknowledged_at`, not from when the alert fired, so a finding you just closed stays visible for the full window regardless of its age. **Pending alerts are never purged**, by construction — retention must not swallow open findings, the same rule scan retention already honours. Global on purpose, unlike the per-schedule scan knob: an acked alert is closed bookkeeping wherever it came from. The purge runs at boot (a manual-scans-only install still ages out) and after every completed scheduled scan, and a purge failure never taints the run. Strict parse as always: zero, negatives and garbage mean *off*, never a window that silently swallows the history.
- [x] **v1.18.0** — **Sensitive port alerts**: eleventh step of the **Network Observability** track, and the first alert about what a device *exposes* rather than how it behaves. Set **`SENSITIVE_PORTS`** (opt-in, e.g. `23,445,3389` — unset = off) and any host found with one of those TCP ports **open** raises a **`sensitive_port`** alert: same sidebar badge, modal, filter chip (red — the most actionable family) and notifier pipeline as the rest. **One alert per host, listing every watched port found on it** — the finding is "this device exposes telnet *and* SMB", and a box with five watched ports open shouldn't drown the sidebar. Like `high_latency` it deliberately **needs no baseline** (it judges the current scan), and it keeps the same honesty rules: only ports the scan actually saw as `open` count, a host that was never port-scanned says nothing about its ports, and closed/filtered are exactly what you want to see. The notifier gains a third family — `partitionAlerts` now splits drift, latency and **exposure**, so a telnet box can page a different channel than a slow one (🔓 red embed, `:unlock:` on Slack, ntfy `Priority: high`). Strict list parse: unusable entries are dropped instead of silently widening the watchlist, and an all-garbage list means *off*. The seeded Windows desktop has 3389 open, so the demo shows one out of the box.
- [x] **v1.19.0** — **Alert export**: completes the export trio — scans (v1.1.0), host history (v1.10.0), and now the alert list. `GET /api/alerts/export?format=csv|json` takes the **same filters as `/api/alerts`** (`cidr`, `unackOnly`, `types`), so what you download is what the sidebar was showing, filter chips included — an export that silently ignored the active filter would be worse than none. No `limit`: the on-screen list is capped at 500 rows, a *report* is the whole set. A GET like its two siblings, so it works on the read-only public demo. The CSV problem is that an alert's payload has **a different shape per type** (a latency finding carries `latency_ms`, an exposure one a port list), so two columns carry it instead of one column per type: **`detail`**, the same human sentence the UI's alert row shows — the one you paste into a ticket — and **`payload_json`**, the raw object for whoever parses it. Plus `status` (pending / acknowledged) and ISO-8601 timestamps for both the firing and the ack. UTF-8 BOM + CRLF like the other exports (Excel opens it without a wizard), and the filename names the scope: `lanscope_alerts_192-168-1-0-24.csv`, or `..._all.csv` unfiltered. The `detail` renderer is deliberately duplicated from the browser bundle (a DOM script can't be required server-side) with a test pinning one line **per alert type** against real payloads — the field names are not guessable (`before`/`after`, `added`/`removed`, `last_seen_hostname`), and a silent divergence would ship a report full of `?` that still looks fine in review.
- [x] **v1.20.0** — **Per-host alert mutes**. Every network has that one device: always there, always chatty, never worth a page — a TV that renegotiates its lease, a laptop that sleeps through half the scans. A 🔕 **Mute alerts** checkbox in the label modal (✎) stops **new alerts of every kind** for that IP on that network — baseline drift, latency and sensitive ports included — while the rest of the LAN keeps alerting normally. Enforced at alert **creation** time in the detectors (the scan pass *and* the v1.18 live portscan hook), not hidden at display time: a muted host produces nothing to notify, count, digest or export, and alerts that already existed stay until acknowledged (a mute is not an eraser). Mutes live in a new `alert_mutes(cidr, ip)` table keyed like labels — the mute follows the device across scans of its network, and the same IP on another network is untouched. Muted rows wear a 🔕 chip next to the hostname. REST: `GET /api/mutes?cidr=…` and an idempotent `PUT /api/mutes` (`muted` must be a **strict boolean** — a truthy `"false"` silently muting a host would be the worst bug to chase). The demo ships the smart TV muted; editing is blocked there by `DEMO_MODE` as usual.
- [x] **v1.21.0** — **Type-scoped mutes**. v1.20's mute was all-or-nothing; the natural next ask is *"the NAS pings slow during its backup window — silence the latency pages, but I still want to know if a new port opens on it"*. The 🔕 checkbox now unfolds into **three family checkboxes** — baseline drift, high latency, sensitive ports (the same buckets the alerts tray uses) — and a subset mutes **just those alert types**, while the rest keep alerting for that host. All three on = mute everything (stored as `types = NULL`, the v1.20 spelling, so **existing mutes keep behaving unchanged** — the new column arrives by soft `ALTER TABLE`, no rebuild); unticking all three is an unmute, because a mute of nothing IS an unmute. Enforced at creation time in **both** detection paths, each spec judged by its own type (`disappeared` included — the scope check rides `payload.ip`, its `host_id` is null). REST: `PUT /api/mutes` grows an optional `types` array — validated against the alert-type list, empty arrays rejected, and a full set **canonicalized to `NULL`** so "everything" has exactly one spelling in the table. The 🔕 chip's tooltip names what's muted. The demo now ships both flavours: the TV fully muted, the NAS latency-only.
- [x] **v1.22.0** — **Mute expiry (snooze)**. v1.20 muted a host, v1.21 muted just some alert kinds — but both were forever, and "the NAS pings slow *during its backup window*" is not a forever problem: a permanent mute relies on a human remembering to unmute. The mute modal gains a **For how long** selector (forever / 1 h / 8 h / 24 h / 7 d / 30 d): a snoozed mute suppresses exactly like before **and re-arms alerting by itself** when the time is up. `alert_mutes` grows a nullable `expires_at` (epoch ms) by soft `ALTER TABLE` — `NULL` means forever, so **every pre-existing mute keeps behaving unchanged**, same recipe as v1.21's `types`. Expired rows are **lazily purged on every read path** (`listMutes` / `getMutes`), so neither the UI nor the detectors ever see a dead mute and no cron is needed; scope and clock expire as one unit (a lapsed latency-only mute silences nothing). REST: `PUT /api/mutes` grows an optional **`until`** (epoch-ms integer) — absolute on purpose, so the UI's *keep current deadline* option round-trips exactly; it must sit in the future (small client clock skew only ever shortens a snooze) and within a year (beyond that you mean "forever", and forever has one spelling: `null`). The 🔕 chip's tooltip names the deadline, re-picking a duration deliberately re-arms the clock, and the demo's NAS mute is now snoozed six hours past seed time so the feature is visible out of the box.
- [x] **v1.23.0** — **Config export / import**. Labels, mutes, schedules and notification channels in one JSON document — the instance's *intent*, portable at last: back it up before wiping the DB, clone it onto a second box, keep it in git. **Scan history stays out on purpose** (it is data, not configuration, and already has its own per-scan exports), and so do runtime fields (ids, last-run/last-sent state). `GET /api/config/export` is a GET on purpose — works on the read-only demo, downloads with a plain sidebar anchor, `lanscope_config: 1` schema marker inside. `POST /api/config/import` **validates the whole document first** (every item through the same validators as the live endpoints — a 400 names the exact offending item, `mutes[3]: unknown alert type…`) **and writes in one transaction**: all-or-nothing, never half a backup. Merge semantics: labels and mutes **upsert** (keyed by network+IP, same as their endpoints); schedules and channels are **skipped when the name already exists** — re-importing a backup must not breed duplicates. A freshly imported schedule starts ticking immediately (scheduler reload), an imported mute with a past deadline is legal (a backup is a snapshot; the lazy purge retires it on first read — pinned by test), and a full `types` set canonicalizes to `NULL` exactly like the live endpoint. UI: a *Config* sidebar section with ⬇ Export (no JS at all) and ⬆ Import (file picker → counts of what landed, skips named). Import is blocked on the demo by the read-only middleware like every other mutation; export works there — try it.
- [x] **v1.24.0** — **Import dry run**. A restore *overwrites names someone typed*, and until now ⬆ Import was a blind button: you picked a file and found out afterwards. `POST /api/config/import?dry_run=1` reports exactly what would happen and writes nothing, so the UI is two steps: pick the file → a confirm names the plan (*"3 labels (1 new, 2 overwritten) · 2 mutes · skipping 1 by name (Nightly sweep)"*) → apply or cancel. **The plan comes from the real code path, not a parallel simulation**: the import runs inside its transaction and then **rolls back** (a sentinel thrown from within aborts it), so what the preview promises is what the write would do — pinned by a test that asserts the dry run and the real import return identical `imported`/`skipped`/`plan`. The plan also splits the counts into **new versus overwritten rows**, which is the one thing worth knowing before saying yes. The flag **fails safe**: any present value means dry run except an explicit `0`/`false`/empty, so a typo like `?dry_run=maybe` yields a preview instead of the unwanted write strict parsing would have caused.
- [x] **v1.25.0** — **API tokens**. Basic Auth (v1.6) guards the browser, but handing the admin password to every cron job and script that polls the API is how the password ends up in shell history and crontabs. A token is a second door with its own key: `POST /api/tokens` mints one (`lsk_` + 64 hex chars — the prefix makes a leak recognizable in logs and secret scanners), shown **once** in the response and stored only as its sha256 (a database read — a backup, a stray copy — yields nothing presentable). `Authorization: Bearer lsk_…` then opens the same door as the Basic credential, static UI and API alike; `last_used_at` answers *"is anyone still using this?"* before a revoke, and `DELETE /api/tokens/:id` cuts a script off immediately without touching the admin password or the other tokens. With auth **off**, minting refuses with a 400 — every door is already open and a token would only pretend to guard something. UI: an *API tokens* sidebar section, shown only when the server reports auth enabled — create by name, see last use, revoke with one click. A malformed or revoked Bearer falls through to the same 401 as a bad Basic credential: one failure shape, nothing to enumerate.
- [x] **v1.26.0** — **Selective config export**. The v1.23 backup is all-or-nothing on the way *out* too — but "hand my labels to a second box" shouldn't drag schedules and webhook URLs along. `GET /api/config/export?sections=labels,mutes` names what the backup carries; the sections it does not carry are **absent keys, not empty arrays**, and the import side already reads absence as *"nothing to restore here"* — so a labels-only backup restores labels and cannot touch schedules someone hand-tuned since. The two halves compose by design, pinned by test. Omitting the parameter keeps the classic full document byte-for-byte; the **full set spelled out collapses to the same thing** (one spelling for "everything", the mute-types precedent); an unknown section is a named 400, an empty list is a mistake (400), not "nothing". The filename says the scope (`lanscope_config_labels+mutes_2026-08-07.json`), so a folder of backups reads at a glance. UI: four checkboxes under *Config* rewrite the ⬇ Export link as you pick; unchecking everything disables it — an empty backup is a mistake, not a document.
- [x] **v1.27.0** — **Selective config import**, the mirror of v1.26 on the way *in*. `POST /api/config/import?sections=schedules` restores only those sections and leaves the rest of the document on the floor — you keep one full backup but drop just the schedules onto a box without clobbering the labels and mutes you curated there since. The sections you don't name are reduced to empty arrays, which `importConfig` already reads as *"touch nothing here"* (the v1.23 merge semantics), so the two features **compose** rather than special-casing each other — pinned by test. It also composes with the v1.24 **dry run**: `?dry_run=1&sections=schedules` previews exactly the scoped subset you'll apply, and the response echoes `"sections"` so you can see what it acted on. Same `?sections=` vocabulary and validator as the export (`validateSectionsParam`): absent = everything, an unknown section is a named 400, the full set spelled out collapses to "all". The **same four checkboxes** under *Config* now scope both directions — pick `schedules`, click ⬆ Import, and only the schedules land; unchecking everything blocks the import (nothing to restore) the way it disables the export link.
- [x] **v1.28.0** — **Prometheus `/metrics`**. The dashboard answers *"how is the LAN right now?"*; a scraper asks *"how has it been, plotted next to everything else I run?"* — and every self-hosted stack already has the answer's home: Prometheus + Grafana. `GET /metrics` (root path, the scrape convention) serves the text exposition format **hand-rolled in one small module** — a client library would weigh more than the format. What it exposes: `lanscope_hosts_up` / `lanscope_hosts_total` and the last scan's clock and duration **per network** (from the latest *finished* scan — a running or errored scan never represents a LAN), `lanscope_alerts_pending` by type (**every known type always present, zero-filled** — "no pending sensitive-port alerts" is a fact worth a series, and its disappearance would make dashboards guess), scans stored/running, schedules enabled/total, and a `lanscope_info{version=…}` marker. **Everything is a gauge on purpose**: these numbers come from a database with retention pruning (`keep_last`, `ALERT_RETENTION_DAYS`), so they can legitimately go *down*, and a Prometheus counter promises monotonicity this data cannot keep — the honest type beats the conventional suffix. It composes with v1.25: when auth is on, the same gate covers `/metrics`, so you **mint an API token for the scraper** (`authorization: credentials` with `Bearer lsk_…` in the scrape config) instead of handing Prometheus the admin password. Works on the read-only demo — `curl https://lanscope-demo.onrender.com/metrics`.

- [x] **v1.29.0** — **API token expiry**. A token that never expires is a password with extra steps — but *forcing* an expiry breaks the homelab cron nobody rotates, so it's optional: `POST /api/tokens` grows `expires_in_days` (a whole number, 1–3650; absent means *never*, so **every v1.25 token keeps behaving unchanged** — `expires_at` is a nullable column added by soft `ALTER TABLE`, the v1.22 mute-snooze recipe applied to credentials). Relative days on purpose: the server computes the deadline from its own clock at mint time, so client skew can't stretch a token's life (the absolute-`until` argument that shaped mute snoozes was about round-tripping an existing deadline; a mint is a one-shot). Expiry is enforced in the lookup the auth middleware uses, so an expired Bearer falls through to the **same bare 401** as a revoked or forged one — one failure shape, nothing to enumerate — and `last_used_at` is never stamped by a refused attempt. One deliberate divergence from the mute recipe: lapsed mutes are lazily *purged* (nothing left to debug), but **an expired token stays in the list, visibly expired** — a lapsed token means someone's script just broke, and *"expired three days ago"* next to its `last_used_at` is the answer to "why". UI: the mint form gains an expiry selector (never / 30 d / 90 d / 1 year) and the list names each token's deadline, bold once it has passed. Verified by the wire: mint with TTL → Bearer 200 → deadline doctored into the past → the same Bearer gets the bare 401 with no restart, and the token stays listed.

## FAQ

### Is it legal to scan a network with LanScope?
On a network you own, manage, or have explicit permission to scan — yes. LanScope is built for your home LAN, your homelab, or a customer network where you've been hired to inventory devices. Scanning a network you don't have permission to scan is illegal in most jurisdictions and is **not** what this tool is for. The project deliberately ships with NSE limited to `default` / `safe` (no `vuln` / `exploit` / `brute`) so it can't be twisted into a remote exploitation tool, but you can still get yourself into trouble by pointing it at someone else's network. Don't.

### Does it work on macOS or Windows?

**Windows** — yes, via **WSL2 with mirrored networking** on Windows 11 22H2 or newer. See the [Windows quickstart](#windows-via-wsl2). A WSL2 distro shares the host's network adapters directly, so `nmap` inside the container sees your real LAN end-to-end. Docker Desktop is *not* the right path even with its WSL2 backend — it wraps containers in its own internal subnet and `network_mode: host` only exposes that. Install Docker Engine inside the WSL distro instead.

**macOS** — not for real scanning. Docker Desktop on macOS runs containers inside a Linux VM with no LAN-bridged option, and there's no WSL2-equivalent path. You can run LanScope to play with the UI, but it'll only see the VM's internal subnet. For real use on a Mac, run LanScope inside a Linux VM with a bridged network adapter on the same LAN you want to scan.

### Does it need root on the host?
No. `nmap` inside the container runs as the unprivileged `node` user; the Dockerfile uses `setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip` on the `nmap` binary so it can craft raw packets without root. What the *container* needs is the two capabilities — `NET_RAW` and `NET_ADMIN` — declared in `cap_add`. Compose handles that.

### How do I put a password on the UI?

Set `AUTH_USER` and `AUTH_PASS` (both — LanScope refuses to start with only one) in the `environment:` block of `docker-compose.yml` and restart the container. Every page and API call then requires the credential via HTTP Basic Auth, and the browser shows its native login prompt. Leave both unset for the default open behaviour on a trusted LAN. If the instance is reachable from outside your network segment, put a TLS reverse proxy in front — Basic Auth over plain HTTP can be read by anyone on the path.

For scripts and cron jobs, don't reuse the admin credential: mint an **API token** in the sidebar (or `POST /api/tokens`) and call the API with `Authorization: Bearer lsk_…` instead — revocable one by one, without ever rotating the admin password (v1.25.0). Since v1.29.0 a token can carry an expiry (`expires_in_days`): it stops opening the door at its deadline with the same bare 401 as a revoked one, but stays in the list, visibly expired — so a cron that breaks at 3 a.m. has its answer waiting in the sidebar.

### Can Prometheus / Grafana scrape it?

Yes — `GET /metrics` serves the Prometheus text format with per-network host counts, last-scan clocks, pending alerts by type, and schedule totals (v1.28.0). With auth enabled, mint an API token for the scraper and put it in the scrape config instead of the admin password:

```yaml
scrape_configs:
  - job_name: lanscope
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: lsk_your_token_here
    static_configs:
      - targets: ["lanscope.lan:3030"]
```

### Where is my data stored?
Locally, in a single SQLite file inside the Docker named volume `lanscope-data` (mounted at `/var/lib/lanscope/lanscope.db` in the container). Nothing leaves the machine. No telemetry, no analytics, no remote calls beyond what `nmap` itself sends across the LAN.

### How do I back up my scans?
Copy the SQLite file out of the volume:

```bash
docker run --rm -v lanscope-data:/data -v "$PWD":/backup alpine \
  cp /data/lanscope.db /backup/lanscope-$(date +%F).db
```

Restoring is the reverse direction. The file is a regular SQLite database; you can also open it with the `sqlite3` CLI to inspect or export tables.

### Why doesn't Wake-on-LAN wake my device?

Three things have to be true at once. **1)** The target must have WOL enabled — in the BIOS/UEFI ("Wake on LAN", "Power On by PCI-E") *and* on the NIC (`ethtool eth0` should show `Wake-on: g`; on Windows, check the adapter's Power Management tab). **2)** The magic packet is a layer-2 broadcast, so LanScope must be on the **same network segment** as the target — in Docker that means `network_mode: host` (which the quickstart already uses); from a routed network or the default bridge the broadcast never arrives. **3)** The scan must have captured the device's **MAC** (the `⏻` button only appears when it did) — the packet is addressed to the NIC, not the IP. Also note most machines only listen for WOL from soft-off / sleep, not after a hard power cut.

### Can I scan a remote network?
Only by running LanScope on a host that's *inside* that network. The CIDR sweep needs L2 reachability for ARP and `nmap`'s discovery probes to mean anything; routing through a VPN can work for the ping sweep but you'll lose MAC addresses and vendor lookups (vendor is derived from the MAC OUI). The supported use case is "homelab / office LAN you can plug into."

### How do I upgrade?
If you pull from GHCR:

```bash
# bump the tag in your docker-compose.yml to the new version
docker compose pull
docker compose up -d
```

If you build from source: `git pull && docker compose up -d --build`. The database migrates itself at boot (`CREATE TABLE IF NOT EXISTS` + idempotent `ALTER`s) so going forward across versions is a no-op for your scan history. Going *backwards* is not supported — older binaries may not understand newer tables, but the existing data won't be destroyed either.

### How do I uninstall?
```bash
docker compose down -v   # removes the lanscope-data volume too
docker image rm ghcr.io/dannyruizb/lanscope:1.0.0  # or whatever tag you have
```

Without the `-v` flag the volume sticks around, so a future `docker compose up -d` resumes with all your history.

### What's the difference between *alerts* (v0.13) and *notifications* (v0.11)?
Alerts are events stored inside LanScope whenever a scan diverges from its CIDR's declared baseline (a new host appeared, a hostname rotated, port 22 opened on a host that didn't have it). They're a queue you triage in the UI — acknowledge, delete, filter by type. Notifications are outbound deliveries to external systems (a webhook URL, a ntfy.sh topic). One feeds the other: when a scan produces alerts, the notifier fires a single aggregated `baseline_diff` event for inventory drift and (since v1.13.0) a separate `high_latency` event for latency findings, each to the channels subscribed to it — a latency page and an inventory-drift alarm rarely want the same destination. You can run alerts without notifications (just watch the sidebar badge), or notifications without alerts (a Discord channel subscribed to `scan_done` doesn't need the baseline machinery).

### When does an alert get created? What if I haven't set a baseline?
After every successful scan (manual or scheduled), LanScope looks up the inventory baseline declared for that CIDR. If one exists, it computes the per-host diff and writes one alert per detected change. If the CIDR has no baseline, the diff is meaningless — no alerts are generated, on purpose. To opt in for a CIDR, run a scan you trust, click *★ Set as baseline*, and from then on every later scan of that CIDR will produce alerts when something changes. Acknowledging an alert keeps it in the list (with an "acked" tag); deleting one removes it permanently; deleting the parent scan cascades and removes its alerts too.

## Troubleshooting

### `nmap: Operation not permitted` even though the container appears to run as root
Docker doesn't grant `NET_RAW` / `NET_ADMIN` by default, and Alpine's `nmap` binary expects them as file capabilities. The supplied `docker-compose.yml` declares both in `cap_add`; if you wrote your own compose, copy that block over.

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

### `could not locate nse_main.lua` when an NSE script runs
The Alpine `nmap` package ships the binary and data files, but **not** the script library. You need the `nmap-scripts` package too. The official image already has it; if you built a slim variant yourself, add it to the Dockerfile:

```
RUN apk add --no-cache nmap nmap-scripts libcap
```

### I changed something under `src/` and ran `docker compose restart`, but the UI is unchanged
The image is built once; `COPY src/ ./src/` runs at build time. `restart` just re-launches the existing image. After editing source, use `docker compose up -d --build` to rebuild. (Lesson learned during v0.5 development — burned about ten minutes wondering why a script-output decode fix wasn't sticking.)

### Port 3030 is already in use
Override the host-side port with the `PORT` environment variable inside the container *and* the host port mapping. The simplest path is to keep `network_mode: host` and just change `PORT`:

```yaml
environment:
  PORT: 3050
```

LanScope binds to `0.0.0.0:$PORT`. If you prefer Docker's normal port mapping, drop `network_mode: host` — but you'll lose real LAN visibility, so that only makes sense if you're scanning the Docker network itself.

### MAC column is empty for some hosts
`nmap` can only fill in MAC addresses for hosts on the **same Layer-2 segment** as the scanning machine. Anything past a router (different subnet) is reachable at L3 but the MAC you'd see would just be the gateway's, so `nmap` doesn't report one. Vendor is derived from MAC, so it follows the same rule.

### Using *Skip discovery* (`-Pn`) on a /24 shows every IP as `up` with no MAC and reason `user-set`
That's `nmap` working as documented: `-Pn` tells it to skip the discovery phase entirely and treat every host as up. With a `/24` you'll get 256 rows, every one of them marked `up` even if the address is unallocated. The trade-off is intentional — `-Pn` is for when ICMP / ARP / SYN-on-443 are all blocked and you want to brute through anyway. Use the default discovery for a realistic alive count.

### `docker pull ghcr.io/dannyruizb/lanscope:…` fails with `unauthorized`
The GHCR package is set to **public** so anonymous pulls should just work. If you're getting `unauthorized` anyway, you probably have stale credentials cached from a previous `docker login ghcr.io`. Try `docker logout ghcr.io && docker pull ghcr.io/dannyruizb/lanscope:latest`. If you're behind a corporate proxy, GHCR is reached via `pkg-containers.githubusercontent.com` and you may need to allow that.

### Container died and now I see `lanscope.db-shm` / `lanscope.db-wal` files
SQLite runs in WAL mode (`PRAGMA journal_mode = WAL`), so a crash leaves the write-ahead log files. They're not corruption — they get checkpointed on the next clean shutdown. To force a checkpoint without restarting:

```bash
docker exec lanscope sqlite3 /var/lib/lanscope/lanscope.db 'PRAGMA wal_checkpoint(TRUNCATE);'
```

If you suspect actual corruption, run `PRAGMA integrity_check;` against the same database; a healthy DB returns `ok`.

## Stack

- **Backend**: Node.js 20 + Express + `better-sqlite3`.
- **Frontend**: vanilla HTML / CSS / JS, no build step.
- **Scanner**: shells out to `nmap` and parses the XML output.
- **Distribution**: Docker image built from `node:20-alpine` plus the Alpine `nmap` package.

## Tests

A [`node:test`](https://nodejs.org/api/test.html) suite covers the pure parts of the scanner — the input validators that guard everything reaching the nmap argv (`validateCidr`, `validatePortsSpec`, `validateDiscovery`, …) and the nmap-XML parsers (`parseHosts`, `parsePorts`, `parseHostScripts`, `parseOsMatches`), fed hand-written `nmap -oX` fixtures. No nmap binary, no network, no host touched — so it runs anywhere, including CI.

```bash
npm install   # dev deps
npm test      # node --test over test/*.test.js
```

CI runs ESLint **and** this suite on every push and pull request (the separate smoke workflow exercises the live container).

## About

Built by **[Danny Ruiz](https://github.com/DannyRuizB)** — systems & network administrator (ASIR, *Administración de Sistemas Informáticos en Red*). [More projects →](https://github.com/DannyRuizB?tab=repositories)

## License

MIT © Danny Ruiz Boluda
