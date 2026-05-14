# Reddit launch drafts — r/selfhosted + r/homelab

Two drafts below. Different audiences, different angle. Reddit accepts
markdown (headers, bold, lists, fenced code) — use it; HN style of "wall of
plain text" reads as effort-less on Reddit.

Post one subreddit at a time, **with at least 24-48 h between them**, to
avoid both:
- the cross-poster's perception ("this guy is spamming the same thing")
- one community's engagement leaking into the other's algorithm

---

## r/selfhosted

### Subreddit rules (verify before posting)

- Read https://www.reddit.com/r/selfhosted/wiki/rules first — the rules page
  is the source of truth.
- They strictly ban self-promotion without context. The rule of thumb on the
  sub is roughly **90% value / 10% link**: the body has to teach something or
  show something useful, not just point at your repo.
- Posts must be self-hostable in the practical sense. LanScope qualifies
  (one container, no external dependencies beyond the LAN itself).
- Flair: pick **`Release`** or **`Software`** when posting (drop-down in the
  post composer). Posts without the right flair get auto-removed in some
  subs.

### Title

```
I built LanScope — a self-hosted web UI for nmap to inventory my homelab LAN
```

(~73 chars. First-person + verb + tagline. Reddit responds well to "I built X".)

### Body

```
After getting tired of running `nmap -sn` and `nmap -sV` against my home
network from a terminal every time I wanted to check what's on it, I built a
small web UI in front of nmap and packaged it as a single Docker container.

It's deliberately *not* a security scanner — no CVE detection, no exploit
modules. The NSE script allowlist is locked to `default` and `safe`. The
point is **visibility**: who's on my LAN, what they expose, what changed
against a known baseline.

**What it does**

- CIDR ping sweep, alive-host table with MAC / vendor / hostname / OS.
- Per-host TCP scan, OS fingerprint, UDP scan, NSE scripts — each via a
  one-click button on the host's row.
- Topology graph (Cytoscape.js) — gateway at the centre, hosts on concentric
  rings by how much I know about them.
- Diff between two scans of the same CIDR — appeared / disappeared / changed
  hostname, MAC or OS family.
- "Set as baseline" on any scan; every later scan auto-compares.
- Scheduled scans (cron) with webhook / ntfy notifications.
- Per-CIDR timeline with hosts-alive, open-ports, scan-duration and
  baseline-diff charts.
- Baseline-divergence alerts — anything new / gone / changed gets queued
  for triage; a red badge in the sidebar shows the unack count.

**Stack and footprint**

Node 20 + Express + better-sqlite3, vanilla JS for the frontend. Multi-arch
image on GHCR (`ghcr.io/dannyruizb/lanscope`, amd64 + arm64). One SQLite
file in a Docker named volume, no external dependencies. Zero telemetry,
zero outbound calls except the notifier channels you opt into.

**Try without installing**

A read-only public demo with three pre-seeded scans of a synthetic
`192.168.1.0/24` runs at https://lanscope-demo.onrender.com. First hit
takes ~10-30 s to wake the free-tier dyno; after that everything is
snappy. Every button that would actually run nmap returns
`Demo mode: scans disabled` — you get to poke at the UI without leaving
my Render account scanning the data centre.

**Caveats**

- Linux host only. The container uses `network_mode: host` for nmap's
  raw packets; on Docker Desktop / macOS / Windows you'd only see the
  Docker VM's internal subnet.
- Same subnet only. Routing through a VPN works for the ping sweep but
  you lose MAC / vendor info.
- Not a security tool. If you want vulnerability scanning, run OpenVAS
  or Greenbone alongside.

**Repo**: https://github.com/DannyRuizB/lanscope
**Docker**: `docker compose up -d` from the README quickstart and you're
running in under 30 s.

Happy to take bug reports / feature requests / PRs. Especially curious
what schedule/notification combos people actually want.
```

### Notes

- The body is ~2.3K chars — comfortable for r/selfhosted, on the long side
  but not too long. They tolerate detail if it's all useful.
- The "what it does" bullet list does the heavy lifting; skimmers can decide
  in 10 s whether to read more.
- The caveats section is important on r/selfhosted — being upfront about
  limitations beats getting "doesn't work on my Mac" complaints in comments.

---

## r/homelab

### Subreddit rules (verify before posting)

- https://www.reddit.com/r/homelab/wiki/rules — read first.
- Flair: pick **`Tutorial`** (if you frame it as "how I solved X") or
  **`Projects`** when posting.
- They are *less* tolerant of self-promotion than r/selfhosted; the body
  must read as "look at this project I'm working on" rather than "buy/use
  my product".

### Title

```
Made a small web UI on top of nmap for keeping track of what's on my homelab LAN
```

(~80 chars. Notice the shift in framing: less "I built a thing", more "I
solved my homelab problem". r/homelab leans hobbyist, that wording fits.)

### Body

```
TL;DR: small Node + SQLite app in a Docker container that turns nmap into a
web UI. Point it at a CIDR, get a table of alive hosts and a topology graph;
click a host to scan its ports / OS / UDP. Everything is stored locally; no
telemetry; no signup; no cloud.

I kept running ad-hoc `nmap` commands from a terminal whenever I wanted to
check my LAN after touching anything (new VLAN, new server, kid plugged a
Switch in, etc.). Eventually I wanted three things at the same time:

1. A list view of "what's alive right now".
2. A way to see what changed since last week.
3. Something I could glance at from my phone.

So I wrote it. It's been running on a Raspberry Pi 4 next to the router
for a few weeks and the topology graph alone has been worth the effort.

**Highlights for a homelab use case**

- Auto-detects the gateway by scanning `.1` and `.254`; puts it at the
  centre of the graph with everything else on rings.
- "Set as baseline" on a scan you trust, and from then on every scan auto-
  highlights anything new / gone / changed. (Useful after a power outage,
  or to spot a guest device on the LAN.)
- Scheduled scans (cron) — I have one running every hour. If anything
  diverges from the baseline, a red badge shows up in the UI and (optionally)
  a webhook / ntfy push fires.
- Multi-arch Docker image, so it runs on a Pi or an x86 NUC without
  thinking about it.
- Per-CIDR timeline of hosts-alive, open-ports and scan-duration over time.

**Demo** (no install, read-only, pre-seeded /24):
https://lanscope-demo.onrender.com

**Code**: https://github.com/DannyRuizB/lanscope (MIT)

**Stack**: Node 20, better-sqlite3, vanilla JS (Cytoscape.js for the graph,
Chart.js for the timeline). One container, one SQLite file in a named
volume, no other dependencies.

Curious if there's a feature anyone really wants — the scheduler and the
alert / notification stack are the newest pieces and I'd like to know what
combinations end up being useful in practice.
```

### Notes

- Body slightly shorter (~1.8K chars) and a TL;DR up top — r/homelab skews
  toward "I'll look at the picture and skim the first paragraph".
- The "I have one running every hour" detail makes it feel real (vs vendor
  marketing).
- Mentioning RPi 4 explicitly is intentional: r/homelab is heavily Pi-
  positive and showing the arm64 image works on the platform earns goodwill.

---

## Cross-cutting rules

- **One post per sub.** No reposting if it doesn't take off — mods will
  notice and that's how you get banned.
- **Stay in the thread.** Engaging in the first 1-2 h after posting hugely
  boosts ranking on both subs. Be there.
- **Comments policy.** If someone complains about scope ("why no CVE
  scanning?"), point at the deliberate decision in the FAQ — don't argue,
  don't promise to add it.
- **Reddit lifetime is short.** A post stays relevant for ~24 h. After 36 h
  it's effectively dead. Pick the day you post on purpose.

## When to post

- **r/selfhosted**: weekday morning UTC (08:00-10:00 in Spain = 02:00-04:00
  PST). The sub is more international, so European hours work fine.
- **r/homelab**: weekday afternoon UTC (15:00-17:00 in Spain = 09:00-11:00
  PST). More US-leaning, peak when US folks log in for work.
- **Order**: Show HN first (Tue-Thu), then r/selfhosted ~48 h later, then
  r/homelab ~48 h after that. Each fresh wave catches a different audience.

## Related drafts

- [HN post](./hn-post.md) — Show HN.
- [awesome-selfhosted entry](./awesome-selfhosted/lanscope.yml) — gated to
  2026-09-04 by their 4-month rule.
