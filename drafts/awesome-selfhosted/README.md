# awesome-selfhosted entry draft

This directory holds a YAML entry ready to be submitted to
[awesome-selfhosted-data](https://github.com/awesome-selfhosted/awesome-selfhosted-data).

## ⏳ When to submit

awesome-selfhosted requires *first released more than 4 months ago*.
LanScope `v0.1.0` was tagged on **2026-05-04**, so the earliest the entry
can be submitted is **2026-09-04**.

A reminder to past-Danny: any PR opened before that date will be closed
with the canned reply about the 4-month rule and you'll have to resubmit
later.

## How to submit (once eligible)

1. Open the [Add a new file flow on awesome-selfhosted-data](https://github.com/awesome-selfhosted/awesome-selfhosted-data/new/master/software).
2. Filename: `lanscope.yml` (kebab-case, matches the project name).
3. Paste the contents of [`lanscope.yml`](./lanscope.yml) in this directory.
4. Commit message: `add LanScope`.
5. Select "Create a new branch for this commit and start a pull request".
6. Submit. Maintainers will review and merge into the main branch.

## What's in the entry

| Field | Value | Why |
|---|---|---|
| `name` | LanScope | Project name |
| `website_url` | GitHub repo | No standalone homepage; the repo serves both roles |
| `source_code_url` | GitHub repo | Same URL is fine |
| `description` | 205 chars, sentence case | Under the 250-char hard cap; avoids the banned words ("open-source", "self-hosted", "free") per their style guide |
| `licenses` | `[MIT]` | Matches `package.json` |
| `platforms` | `[Nodejs, Docker]` | Both apply: pure Node app, distributed as a multi-arch Docker image |
| `tags` | `[Network Utilities]` | The tag's own description says: *"tools and software that help manage, monitor, and troubleshoot computer networks"* — perfect match. `Monitoring & Status Pages` is `redirect:`-ed to awesome-sysadmin so it can't be used |
| `demo_url` | Render demo | Lets reviewers see the UI without installing |

## If anything changes before submission

Things that would invalidate the entry and need updating before sending the PR:

- Repo moves or is renamed → bump both URLs.
- License changes → bump `licenses:` (and the SPDX identifier must already exist in [`licenses.yml`](https://github.com/awesome-selfhosted/awesome-selfhosted-data/blob/master/licenses.yml) of the data repo).
- The demo at `lanscope-demo.onrender.com` is decommissioned → drop the `demo_url:` line entirely (it's optional).
- The project changes scope significantly (e.g. becomes a security scanner with CVE detection, an explicit non-goal as of v0.13) → re-write the description to match reality, and consider whether `Network Utilities` still fits.

## Related tasks (still pending)

- **C.2** — Show HN post draft
- **C.3** — Reddit posts for r/selfhosted + r/homelab

Both are not gated by the 4-month rule and can go out as soon as v1.0 ships.
