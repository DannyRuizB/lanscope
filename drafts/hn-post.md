# Show HN post — draft

Ready to submit once v1.0.0 is tagged and the public demo is updated.
Paste the title into the "title" field on https://news.ycombinator.com/submit,
paste the URL into the "url" field, leave the "text" field empty, then post
the first comment immediately so it appears at the top of the thread.

## Title (≤80 chars — HN truncates at ~80 in the front-page list)

```
Show HN: LanScope – visual LAN scanner on top of nmap, runs in Docker
```

(70 chars, fits comfortably. Reads as "Show HN: $NAME – $TAGLINE".)

## URL field

```
https://github.com/DannyRuizB/lanscope
```

(Repo, not the demo — HN expects the canonical project URL. The demo link
goes in the text body so it's visible to people who never click the URL.)

## Text field (leave empty)

HN's Show-HN convention: if the URL is the project itself, the text field
stays empty so the post links straight to the repo. Use the **first comment**
to add narrative.

## First comment (post immediately after submission)

```
A few things on why this exists and what's in scope:

I wanted a docker-compose-friendly way to inventory my homelab LAN without
dropping back to a terminal every time. Every tool I tried was either CLI-only
or stuck in a 2005 desktop UI; Zenmap exists but feels abandoned. So LanScope
is a small web UI in front of nmap — point it at a CIDR, get a table of alive
hosts and a topology graph, click a host to run TCP/UDP/OS scans, all stored
locally in SQLite.

It's deliberately *not* a security scanner — no CVE database, no exploit
detection. NSE script categories are restricted to `default` and `safe`; the
allowlist is enforced server-side before anything reaches execFile. The goal
is *visibility*: who's there, what they expose, what changed against a
declared baseline.

Some things you can poke at:
- Topology graph (Cytoscape) with the gateway at the centre and hosts on
  concentric rings by relevance (open ports + OS detected → inner ring; just
  alive → outer ring).
- Diff between any two scans of the same CIDR (appeared / disappeared /
  changed mac / hostname / OS).
- Baseline you can declare on any scan, after which every later scan of the
  same CIDR auto-compares against it.
- Scheduled scans (node-cron) with per-channel notifications to webhook
  (generic / Discord / Slack format) or ntfy.sh.
- Per-CIDR timeline aggregating every historical scan (Chart.js).
- Baseline-divergence alerts with ack/triage in the UI.

Read-only demo with three pre-seeded scans of a synthetic /24 lives at
https://lanscope-demo.onrender.com — first hit takes ~10-30 s to wake the
free-tier dyno, then it's instant.

Stack: Node 20, Express, better-sqlite3, vanilla JS frontend. Multi-arch
Docker image on GHCR (linux/amd64 + linux/arm64). No telemetry, no outbound
calls except the notifier channels you opt into.

Caveats: needs a Linux host (the container uses `network_mode: host` for raw
nmap probes; on Docker Desktop / macOS / Windows you only see the VM's
internal subnet). Sites you don't own / don't have permission to scan are
out of scope and the FAQ in the README says so explicitly.

Happy to answer technical questions and take bug reports / PRs.
```

## Tone / etiquette checklist

- No "I'm excited to announce…", no "Today I'm launching…" — HN dislikes
  marketing tone. The first sentence is "I wanted a docker-compose-friendly
  way to…" which reads like a developer talking, not PR copy.
- No emojis or hashtags. No "🚀".
- Use a single backtick for inline code (`network_mode: host`), triple for
  blocks if needed. HN supports neither bold nor headers in comments —
  paragraphs and bullets are the whole tool.
- Stay in the thread for the first 4-6 hours after posting. Replies in the
  first hour disproportionately drive ranking. Be ready to answer "why not
  X?" type questions calmly.
- If someone says it should detect CVEs, point at the explicit scope decision
  and the NSE allowlist. Don't get defensive — say what it is and what it
  isn't.

## When NOT to post

- Don't post on a Friday evening or Saturday — Show HN dies on weekends.
- Don't post during a major news cycle on tech (an Anthropic / OpenAI launch,
  Apple event, etc.) — your post will get buried.
- Best windows: Tuesday-Thursday, 08:00-10:00 Pacific (16:00-18:00 in Spain
  for Danny). HN traffic peaks in US working hours.
- One post per project. If it doesn't take off, **don't repost the same day**
  — that gets flagged. Wait 1-2 weeks if you want to try again with a
  different angle.

## Expected outcomes

- Realistic best case: 50-200 upvotes, front page of Show HN for a few hours,
  a couple of bug reports and a feature request or two.
- Realistic median case: 5-20 upvotes, never hits the front page, but you
  get a handful of genuinely interested users.
- Worst case: 0-2 upvotes, slides off in an hour. Doesn't matter — the post
  still lives on the repo's HN search results and on Google.

## Related drafts

- [Reddit posts (r/selfhosted, r/homelab)](./reddit-posts.md) — fire those
  the same week or the week after HN. Different audience, different tone.
- [awesome-selfhosted entry](./awesome-selfhosted/lanscope.yml) — gated to
  2026-09-04 by their 4-month rule.
