const path = require("node:path");
const express = require("express");
const db = require("./db");
const { validateCidr, runPingSweep, runPortScan } = require("./scanner");

const PORT = parseInt(process.env.PORT, 10) || 3030;

const app = express();
app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/scans", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  res.json({ scans: db.listScans(limit) });
});

app.get("/api/scans/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const scan = db.getScan(id);
  if (!scan) return res.status(404).json({ error: "scan not found" });
  res.json(scan);
});

app.delete("/api/scans/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const ok = db.deleteScan(id);
  if (!ok) return res.status(404).json({ error: "scan not found" });
  res.status(204).end();
});

app.post("/api/scan", async (req, res) => {
  const { cidr } = req.body || {};
  const error = validateCidr(cidr);
  if (error) return res.status(400).json({ error });

  const scanId = db.startScan(cidr);
  try {
    const hosts = await runPingSweep(cidr);
    db.finishScan(scanId, hosts);
    res.json(db.getScan(scanId));
  } catch (e) {
    db.failScan(scanId, e.message);
    res.status(500).json({ error: e.message, scan_id: scanId });
  }
});

app.post("/api/hosts/:id/portscan", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "invalid id" });
  const host = db.getHost(id);
  if (!host) return res.status(404).json({ error: "host not found" });
  if (host.status !== "up") return res.status(400).json({ error: "host is not up" });

  try {
    const ports = await runPortScan(host.ip);
    const saved = db.saveHostPorts(id, ports);
    const refreshed = db.getHost(id);
    res.json({
      host_id: id,
      ip: host.ip,
      portscanned_at: refreshed.portscanned_at,
      ports: saved,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`LanScope listening on http://0.0.0.0:${PORT}`);
});
