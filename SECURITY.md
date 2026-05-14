# Security policy

## Supported versions

LanScope is a personal homelab project. Only the **latest tagged release** receives security fixes. Pin to a specific version (`ghcr.io/dannyruizb/lanscope:0.13.1`) in production and upgrade when a fix lands.

| Version | Supported          |
| ------- | ------------------ |
| latest (0.13.1) | ✅ |
| < 0.13.1 | ❌ (please upgrade) |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use **GitHub's private security advisory** instead:

1. Go to <https://github.com/DannyRuizB/lanscope/security/advisories/new>
2. Fill in the form (affected version, reproduction steps, impact)
3. Submit — only the maintainer sees it

You can expect:

- An acknowledgement within a few days. This is a side project, not staffed 24/7.
- A fix shipped as a patch release on the relevant minor line. If the issue affects the published Docker image, the next tagged image on GHCR will include the fix.
- A coordinated disclosure timeline before the advisory is made public.

## Scope

LanScope sits on top of `nmap` and exposes a web UI on the local host. Realistic threat models include:

- **Validation bypasses** that let unvalidated input reach `execFile("nmap", …)` — the entire scanner module is built around strict allowlist validation; report any path that breaks that.
- **Stored XSS** in the web UI from data that came back from `nmap` (hostnames, vendor names, banner output, NSE script output) or from alert payloads.
- **Path / SSRF / command injection** in the API endpoints (`/api/scan`, `/api/hosts/:id/*`, `/api/inventory`, `/api/schedules`, `/api/notifications`, `/api/alerts`).
- **SSRF via notification channels** — webhook URLs and ntfy server URLs are validated to be http(s) only; report any path that lets a channel reach a non-HTTP scheme or an internal metadata endpoint outside the allowlist.
- **SQL injection** — every user-supplied value passes through `better-sqlite3` parameterised placeholders. Some `listAlerts` filters compose SQL dynamically, but only out of a fixed set of column expressions; report any code path that interpolates request input directly into a SQL string.

**Out of scope**:

- The fact that `nmap` itself can probe ports — that is the intended behaviour.
- Misuse against networks the user does not own. That is a *user* problem, not a *tool* problem. See the FAQ in the README.
- DoS by scanning a `/8` — anyone with root in the container can do that, and the threat model assumes the operator runs LanScope themselves.

## Hardening notes

LanScope already applies a few baseline hardening measures:

- `nmap` runs with file capabilities (`cap_net_raw`, `cap_net_admin`, `cap_net_bind_service`) and not as root inside the container.
- All `nmap` invocations go through `execFile` with an explicit argument array — never through a shell.
- CIDR / port / timing / scan-technique / NSE-script / discovery-flag inputs are validated against strict allowlists before reaching `execFile`.
- NSE script categories `vuln`, `exploit`, `brute`, `intrusive`, `dos` are deliberately not exposed.
- Notification channels are restricted to two types (`webhook` and `ntfy`) with allowlist validation: webhook URLs must be `http(s)://…`, ntfy topics match `[A-Za-z0-9_-]{1,64}`, and every outbound request runs with a 5 s `AbortSignal.timeout`.
- In `DEMO_MODE`, every state-changing request returns `403` and the notifier short-circuits before any outbound HTTP — the public Render demo cannot reach a downstream service even if a fixture channel were re-enabled.
- The Docker image uses `node:20-alpine` as a small, well-maintained base.

These are not a substitute for keeping the image up to date — pull `:latest` (or the newest pinned tag) regularly, especially after a Node.js or Alpine security advisory.
