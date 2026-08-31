'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createLoginThrottle } = require('../src/login-throttle');

// An injectable clock: the window logic is tested by moving time, never by
// sleeping (the mute-expiry test discipline).
function fakeClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

test('five failures close the door, and the fifth attempt itself was still evaluated', () => {
  const clock = fakeClock();
  const th = createLoginThrottle({ maxAttempts: 5, windowMs: 60_000, now: clock.now });
  for (let i = 0; i < 5; i++) {
    assert.equal(th.check('10.0.0.1').limited, false, `attempt ${i + 1} still allowed`);
    th.recordFailure('10.0.0.1');
  }
  const gate = th.check('10.0.0.1');
  assert.equal(gate.limited, true);
  assert.ok(gate.retryAfterSec >= 1 && gate.retryAfterSec <= 60);
});

test('the deadline is set by the FIRST failure — refusals do not stretch the window', () => {
  const clock = fakeClock();
  const th = createLoginThrottle({ maxAttempts: 2, windowMs: 60_000, now: clock.now });
  th.recordFailure('a');
  clock.advance(30_000);
  th.recordFailure('a');
  // 30 s into a 60 s window: 30 s remain, however many times we knock.
  assert.equal(th.check('a').retryAfterSec, 30);
  clock.advance(10_000);
  assert.equal(th.check('a').retryAfterSec, 20);
});

test('the window lapsing reopens the door and forgets the count', () => {
  const clock = fakeClock();
  const th = createLoginThrottle({ maxAttempts: 2, windowMs: 60_000, now: clock.now });
  th.recordFailure('a');
  th.recordFailure('a');
  assert.equal(th.check('a').limited, true);
  clock.advance(60_000);
  assert.equal(th.check('a').limited, false);
  // The lapsed entry was purged, not decremented: one new failure is 1/2.
  th.recordFailure('a');
  assert.equal(th.check('a').limited, false);
});

test('a successful login clears the slate immediately', () => {
  const th = createLoginThrottle({ maxAttempts: 2, windowMs: 60_000 });
  th.recordFailure('a');
  th.recordSuccess('a');
  th.recordFailure('a');
  assert.equal(th.check('a').limited, false);
});

test('addresses are isolated — one bot cannot spend the office\'s budget', () => {
  const th = createLoginThrottle({ maxAttempts: 1, windowMs: 60_000 });
  th.recordFailure('203.0.113.9');
  assert.equal(th.check('203.0.113.9').limited, true);
  assert.equal(th.check('192.168.1.10').limited, false);
});

test('lazy purge: a stale entry dies on the next touch, so the map cannot grow unbounded', () => {
  const clock = fakeClock();
  const th = createLoginThrottle({ maxAttempts: 5, windowMs: 60_000, now: clock.now });
  th.recordFailure('a');
  th.recordFailure('b');
  assert.equal(th.size(), 2);
  clock.advance(60_000);
  th.check('a');
  th.recordFailure('b'); // purges the stale 'b' first, then records anew (count 1)
  assert.equal(th.size(), 1);
  assert.equal(th.check('b').limited, false);
});

test('retryAfterSec never reports 0 while limited (Retry-After: 0 reads as "now", a lie)', () => {
  const clock = fakeClock();
  const th = createLoginThrottle({ maxAttempts: 1, windowMs: 1000, now: clock.now });
  th.recordFailure('a');
  clock.advance(999);
  const gate = th.check('a');
  assert.equal(gate.limited, true);
  assert.equal(gate.retryAfterSec, 1);
});
