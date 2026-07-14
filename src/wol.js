// Wake-on-LAN: build and broadcast the "magic packet" — six 0xFF bytes
// followed by the target MAC repeated sixteen times, sent over UDP. The NIC
// firmware watches for that pattern even while the machine is off, provided
// WOL is enabled in the BIOS/UEFI and the OS left the NIC's wake flag on.
//
// The packet is layer-2 magic: it only works when the broadcast actually
// reaches the target's segment. From the same LAN (or a container with
// network_mode: host) it does; from a routed network or Docker's default
// bridge it doesn't.

const dgram = require("dgram");

// Accepts the common spellings — aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF and
// Cisco's aabb.ccdd.eeff — and returns the 6 raw bytes, or null if the
// string isn't a MAC.
function parseMac(mac) {
  const hex = String(mac || "")
    .trim()
    .toLowerCase()
    .replace(/[:\-.]/g, "");
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return Buffer.from(hex, "hex");
}

// 102 bytes: FF FF FF FF FF FF + MAC ×16. Returns null on an invalid MAC.
function buildMagicPacket(mac) {
  const m = parseMac(mac);
  if (!m) return null;
  const packet = Buffer.alloc(6 + 16 * 6, 0xff); // the 6-byte header stays 0xff
  for (let i = 0; i < 16; i++) m.copy(packet, 6 + i * 6);
  return packet;
}

// Sends the magic packet and resolves once the datagram left the socket.
// Port 9 ("discard") is the conventional WOL port; the payload is what
// matters, nothing listens on the other end.
function sendWake(mac, { address = "255.255.255.255", port = 9 } = {}) {
  const packet = buildMagicPacket(mac);
  if (!packet) return Promise.reject(new Error(`invalid MAC address: ${mac}`));
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", (err) => {
      socket.close();
      reject(err);
    });
    // setBroadcast requires a bound socket, so bind explicitly first.
    socket.bind(0, () => {
      socket.setBroadcast(true);
      socket.send(packet, port, address, (err) => {
        socket.close();
        if (err) reject(err);
        else resolve({ address, port, bytes: packet.length });
      });
    });
  });
}

module.exports = { parseMac, buildMagicPacket, sendWake };
