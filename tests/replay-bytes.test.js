import test from 'node:test';
import assert from 'node:assert/strict';
import { ReplayWindow } from '../src/engine/replay.js';
import {
  toHex, fromHex, u16, u32, r16, r32, concat, constantTimeEqual, parseIPv4Address, formatIPv4Address,
  isValidIPv4, indexOfBytes, hex32, SimError,
} from '../src/engine/bytes.js';

test('replay window: increasing sequence numbers are accepted', () => {
  const w = new ReplayWindow(32);
  for (let s = 1; s <= 10; s++) {
    const c = w.check(s);
    assert.equal(c.ok, true);
    assert.equal(c.kind, 'new');
    w.update(s);
  }
  assert.equal(w.highest, 10);
});

test('replay window: duplicate rejected, check() does not change state', () => {
  const w = new ReplayWindow(32);
  w.update(5);
  assert.equal(w.check(5).ok, false);
  assert.equal(w.check(5).kind, 'duplicate');
  assert.match(w.check(5).reason, /REPLAY DETECTED/);
  w.check(6);
  assert.equal(w.highest, 5, 'check must not move the window');
  assert.equal(w.seen.has(6), false);
});

test('replay window: out-of-order packets inside the window are accepted once', () => {
  const w = new ReplayWindow(32);
  w.update(1);
  w.update(40);
  assert.equal(w.check(20).kind, 'in-window');
  w.update(20);
  assert.equal(w.check(20).ok, false);
});

test('replay window: packets at or below the left edge are too old', () => {
  const w = new ReplayWindow(32);
  w.update(100);
  assert.equal(w.check(68).kind, 'too-old'); // 100 - 32 = 68 -> left edge is 69
  assert.equal(w.check(69).ok, true);
  assert.equal(w.check(69).kind, 'in-window');
});

test('replay window: sequence 0 and out-of-range values are invalid', () => {
  const w = new ReplayWindow(32);
  assert.equal(w.check(0).ok, false);
  assert.equal(w.check(-1).ok, false);
  assert.equal(w.check(2 ** 32).ok, false);
  assert.equal(w.check(1.5).ok, false);
});

test('replay window: reset clears state; snapshot reports the window', () => {
  const w = new ReplayWindow(32);
  w.update(1); w.update(2); w.update(4);
  const snap = w.snapshot();
  assert.equal(snap.highest, 4);
  assert.deepEqual(snap.cells.map((c) => [c.seq, c.accepted]), [[1, true], [2, true], [3, false], [4, true]]);
  w.reset();
  assert.equal(w.highest, 0);
  assert.equal(w.check(1).ok, true);
});

test('replay window: old entries are pruned when the window slides', () => {
  const w = new ReplayWindow(32);
  for (let s = 1; s <= 100; s++) w.update(s);
  assert.ok(w.seen.size <= 32);
});

test('byte helpers', () => {
  assert.equal(toHex(u32(0xdeadbeef)), 'deadbeef');
  assert.equal(r32(u32(0xdeadbeef), 0), 0xdeadbeef);
  assert.equal(r16(u16(0xabcd), 0), 0xabcd);
  assert.equal(hex32(0x1001), '0x00001001');
  assert.equal(toHex(fromHex('de ad:BE ef')), 'deadbeef');
  assert.throws(() => fromHex('abc'), SimError);
  assert.throws(() => fromHex('zz'), SimError);
  assert.equal(toHex(concat(Uint8Array.of(1), Uint8Array.of(2, 3))), '010203');
});

test('constantTimeEqual', () => {
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)), true);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)), false);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2)), false);
});

test('IPv4 address parsing and validation', () => {
  assert.equal(formatIPv4Address(parseIPv4Address('192.168.1.10')), '192.168.1.10');
  for (const bad of ['', '1.2.3', '1.2.3.4.5', '256.1.1.1', 'a.b.c.d', '1.2.3.-4', '1..2.3']) {
    assert.equal(isValidIPv4(bad), false, bad);
  }
  assert.equal(isValidIPv4('0.0.0.0'), true);
});

test('indexOfBytes finds sub-sequences', () => {
  const hay = Uint8Array.of(1, 2, 3, 4, 5);
  assert.equal(indexOfBytes(hay, Uint8Array.of(3, 4)), 2);
  assert.equal(indexOfBytes(hay, Uint8Array.of(4, 3)), -1);
  assert.equal(indexOfBytes(hay, new Uint8Array(0)), -1);
});
