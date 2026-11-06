"use strict";

// v1.58.0 — the container health probe.
//
// GET /healthz answers 200 {"status":"ok"} when the database can be read, and
// 503 {"status":"unavailable"} when it cannot. It sits ABOVE requireAuth on
// purpose: Docker's HEALTHCHECK has no credential to present, and the answer
// says nothing an anonymous visitor could use - no version, no counts, and
// never the error text (that goes to the server log instead).
//
// `ping` is any function that throws when the database is not usable; the
// server passes db.ping, which reads the schema page.
function healthz(ping, log = console.error) {
  return (req, res) => {
    try {
      ping();
      res.set("cache-control", "no-store").json({ status: "ok" });
    } catch (err) {
      log(`[lanscope] health check failed: ${err && err.message ? err.message : err}`);
      res.status(503).set("cache-control", "no-store").json({ status: "unavailable" });
    }
  };
}

module.exports = { healthz };
