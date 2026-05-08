# LanScope

> Visual LAN scanner for your home network or homelab — point it at a CIDR, see who's there.

> 📸 *Screenshot refresh pending — a new image showcasing the v0.6.1 visual overhaul (light / dark theme toggle, bulk scans, port hints, refreshed palette) will land with the v0.7 topology graph release. To see the current UI, [run it locally](#use-it).*

🚧 Work in progress — v0.6.1.

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

- **Linux only.** `network_mode: host` doesn't behave the same on Docker Desktop for macOS / Windows: the container would only see Docker's internal network, not your real LAN.
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
- [ ] **v0.7** — Topology graph (Cytoscape), diff between scans (appeared / disappeared / changed), and re-scan from the UI without having to delete the scan first.
- [ ] **v0.8** — Declared-host inventory with alerts on deviation. Pre-built Docker image published to GitHub Container Registry (`ghcr.io/dannyruizb/lanscope`) so a one-line `docker pull` skips the local build. Expanded README with FAQ and troubleshooting section.

## Stack

- **Backend**: Node.js 20 + Express + `better-sqlite3`.
- **Frontend**: vanilla HTML / CSS / JS, no build step.
- **Scanner**: shells out to `nmap` and parses the XML output.
- **Distribution**: Docker image built from `node:20-alpine` plus the Alpine `nmap` package.

## License

MIT © Danny Ruiz Boluda
