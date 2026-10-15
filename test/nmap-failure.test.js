'use strict';

// nmapFailure (v1.54.0): the two ways a non-root nmap loses its raw sockets
// must name the fix. Both errors below are the shapes measured in the
// container: a missing NET_ADMIN gives Node's bare "spawn EPERM" (syscall
// "spawn"), no-new-privileges gives nmap's own "Couldn't open a raw socket".

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { nmapFailure, execNmap } = require('../src/scanner');

test('execNmap: a spawn error Node throws synchronously still reaches the callback', async () => {
  // A NUL byte in argv makes execFile throw before anything runs - the same
  // path a real EPERM takes (that one needs a capability-less container).
  let sync = true;
  const err = await new Promise((resolve) => {
    const ret = execNmap('nmap', ['a\0b'], {}, (e, stdout, stderr) => {
      assert.equal(sync, false, 'callback must not run synchronously');
      assert.equal(stdout, '');
      assert.equal(stderr, '');
      resolve(e);
    });
    assert.equal(ret, null);
    sync = false;
  });
  assert.equal(err.code, 'ERR_INVALID_ARG_VALUE');
});

test('nmapFailure: spawn EPERM names the missing capability', () => {
  const err = Object.assign(new Error('spawn EPERM'), { code: 'EPERM', syscall: 'spawn', errno: -1 });
  const e = nmapFailure(err, '');
  assert.match(e.message, /^nmap could not start \(EPERM\)/);
  assert.match(e.message, /NET_RAW and NET_ADMIN/);
  // "spawn nmap" is how Node spells it for other codes: same treatment
  assert.match(nmapFailure(Object.assign(new Error('x'), { code: 'EPERM', syscall: 'spawn nmap' }), '').message, /NET_ADMIN/);
});

test('nmapFailure: a raw-socket refusal keeps nmap\'s words and adds the hint', () => {
  const stderr = "Couldn't open a raw socket. Error: (1) Operation not permitted\nQUITTING!";
  const e = nmapFailure(Object.assign(new Error('Command failed'), { code: 1 }), Buffer.from(stderr));
  assert.ok(e.message.startsWith(`nmap failed: ${stderr}`));
  assert.match(e.message, /no-new-privileges/);
});

test('nmapFailure: any other failure is reported as before', () => {
  assert.equal(nmapFailure(new Error('boom'), Buffer.from('Failed to resolve "nope".\n')).message, 'nmap failed: Failed to resolve "nope".');
  assert.equal(nmapFailure(Object.assign(new Error('spawn nmap ENOENT'), { code: 'ENOENT', syscall: 'spawn nmap' }), '').message, 'nmap failed: spawn nmap ENOENT');
});
