"use strict";

// ===== Login throttling (v1.35.0) =====
// The login form is where humans — and credential-stuffing bots — type
// passwords, and until now it answered every guess at full speed. This
// throttles FAILED attempts per client address with a fixed window: after
// maxAttempts failures the address waits out the remainder of the window,
// and a successful login clears its slate.
//
// Decisions, in the repo's usual order of argument:
//   - In-memory on purpose, no table. This is transient defense state, not
//     configuration: a restart clearing it is fine (restarting is an admin
//     action, and the attacker's budget resets to five guesses, not zero).
//     The DB stores intent; this stores weather.
//   - A throttled attempt is refused BEFORE the credential is evaluated —
//     the refusal costs nothing, and the window does not stretch while
//     limited (the deadline is set by the FIRST failure, so "try again in
//     N s" is a promise that holds instead of a horizon that recedes).
//   - Only /api/login is throttled. Basic and Bearer are high-entropy
//     machine credentials on every request — throttling them would let one
//     forged header lock the admin out of their own dashboard (an anti-
//     brute-force control that doubles as a DoS is the rate-limit-inverted
//     smell from the firewall linter, grown legs).
//   - Keyed by the socket's peer address (the v1.31 binding precedent:
//     a forwarded header is attacker-writable, so behind a reverse proxy
//     this is the proxy's address — the throttle then guards the TOTAL
//     guess rate through that proxy, which is the honest thing available).
//   - Entries are lazily purged on every touch (the mute-expiry recipe):
//     no timer, nothing to leak — an abandoned entry dies the next time
//     anything looks at the map after its window lapses.

function createLoginThrottle({ maxAttempts = 5, windowMs = 15 * 60_000, now = Date.now } = {}) {
  const attempts = new Map(); // address -> { count, firstAt }

  function purgeIfStale(addr, t) {
    const e = attempts.get(addr);
    if (e && t - e.firstAt >= windowMs) attempts.delete(addr);
  }

  return {
    // { limited, retryAfterSec } — retryAfterSec only meaningful when limited.
    check(addr) {
      const t = now();
      purgeIfStale(addr, t);
      const e = attempts.get(addr);
      if (!e || e.count < maxAttempts) return { limited: false, retryAfterSec: 0 };
      return { limited: true, retryAfterSec: Math.max(1, Math.ceil((e.firstAt + windowMs - t) / 1000)) };
    },
    recordFailure(addr) {
      const t = now();
      purgeIfStale(addr, t);
      const e = attempts.get(addr);
      if (e) e.count += 1;
      else attempts.set(addr, { count: 1, firstAt: t });
    },
    recordSuccess(addr) {
      attempts.delete(addr);
    },
    // For tests and /metrics-style introspection: how many addresses are
    // currently being tracked (stale ones not yet purged included — this
    // reads the map, it does not sweep it).
    size() {
      return attempts.size;
    },
  };
}

module.exports = { createLoginThrottle };
