# Security policy

## Supported versions

LanScope is a personal homelab project. Only the **latest tagged release** receives security fixes. Pin to a specific version (`ghcr.io/dannyruizb/lanscope:0.8.3`) in production and upgrade when a fix lands.

| Version | Supported          |
| ------- | ------------------ |
| latest (0.8.3) | ✅ |
| < 0.8.3 | ❌ (please upgrade) |

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
- **Stored XSS** in the web UI from data that came back from `nmap` (hostnames, vendor names, banner output, NSE script output).
- **Path / SSRF / command injection** in the API endpoints (`/api/scan`, `/api/hosts/:id/*`, `/api/inventory`).
- **SQL injection** — the project uses `better-sqlite3` prepared statements exclusively; any code path that builds SQL with string concatenation is a bug.

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
- The Docker image is multi-stage where possible and uses `node:20-alpine` as a small, well-maintained base.

These are not a substitute for keeping the image up to date — pull `:latest` (or the newest pinned tag) regularly, especially after a Node.js or Alpine security advisory.
