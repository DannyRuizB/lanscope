"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const dgram = require("node:dgram");

const { parseMac, buildMagicPacket, sendWake } = require("../src/wol");

test("parseMac accepts colon, hyphen and Cisco dot notation, any case", () => {
  const expected = Buffer.from("aabbccddeeff", "hex");
  for (const s of ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF"]) {
    assert.deepEqual(parseMac(s), expected, s);
  }
});

test("parseMac rejects non-MACs", () => {
  for (const s of ["", null, undefined, "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff", "192.168.1.1"]) {
    assert.equal(parseMac(s), null, String(s));
  }
});

test("buildMagicPacket is 102 bytes: FF×6 then the MAC ×16", () => {
  const packet = buildMagicPacket("aa:bb:cc:dd:ee:ff");
  assert.equal(packet.length, 102);
  assert.deepEqual(packet.subarray(0, 6), Buffer.alloc(6, 0xff));
  const mac = Buffer.from("aabbccddeeff", "hex");
  for (let i = 0; i < 16; i++) {
    assert.deepEqual(packet.subarray(6 + i * 6, 12 + i * 6), mac, `repetition ${i}`);
  }
});

test("buildMagicPacket returns null on an invalid MAC", () => {
  assert.equal(buildMagicPacket("not-a-mac"), null);
});

test("sendWake rejects on an invalid MAC without opening a socket", async () => {
  await assert.rejects(sendWake("nope"), /invalid MAC address/);
});

test("sendWake delivers the magic packet over UDP", async () => {
  // A loopback UDP listener stands in for the network: same datagram path,
  // no broadcast leaves the machine during the test run.
  const received = new Promise((resolve) => {
    const server = dgram.createSocket("udp4");
    server.once("message", (msg) => {
      server.close();
      resolve(msg);
    });
    server.bind(0, "127.0.0.1", async () => {
      const { port } = server.address();
      await sendWake("aa:bb:cc:dd:ee:ff", { address: "127.0.0.1", port });
    });
  });
  const msg = await received;
  assert.deepEqual(msg, buildMagicPacket("aa:bb:cc:dd:ee:ff"));
});
