// IPv4 header construction, checksum, parsing, TTL and mutable-field handling.
//
// Reference vector: the widely used worked example of the IPv4 header checksum
// (header 4500 0073 0000 4000 4011 [checksum] c0a8 0001 c0a8 00c7 -> checksum 0xb861), published in the
// Wikipedia article "IPv4" / "Internet checksum"; the algorithm itself is RFC 791 + RFC 1071.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ipv4Checksum, verifyIPv4Checksum, buildIPv4Header, parseIPv4, rewriteIPv4, routerForward,
  zeroMutableFields, makePlainPacket, PROTO, MUTABLE_FIELDS,
} from '../src/engine/ipv4.js';
import { fromHex, toHex, encoder, SimError } from '../src/engine/bytes.js';


test('checksum of the published worked example is 0xb861', () => {
  const h = fromHex('45000073000040004011' + '0000' + 'c0a80001' + 'c0a800c7');
  assert.equal(ipv4Checksum(h), 0xb861);
  h[10] = 0xb8;
  h[11] = 0x61;
  assert.equal(verifyIPv4Checksum(h), true);
});

test('buildIPv4Header produces a valid, parseable header', () => {
  const h = buildIPv4Header({ src: '192.168.1.10', dst: '192.168.2.20', protocol: PROTO.APP, payloadLength: 34, ttl: 64, id: 7 });
  assert.equal(h.length, 20);
  const ip = parseIPv4(h);
  assert.equal(ip.valid, true);
  assert.equal(ip.version, 4);
  assert.equal(ip.ihl, 5);
  assert.equal(ip.totalLength, 54);
  assert.equal(ip.id, 7);
  assert.equal(ip.ttl, 64);
  assert.equal(ip.protocol, 253);
  assert.equal(ip.src, '192.168.1.10');
  assert.equal(ip.dst, '192.168.2.20');
  assert.equal(ip.flags.df, true);
  assert.equal(ip.flags.mf, false);
  assert.equal(ip.fragmentOffset, 0);
  assert.equal(ip.checksumValid, true);
});

test('checksum validation catches any single-bit header corruption', () => {
  const h = buildIPv4Header({ src: '10.0.0.1', dst: '10.0.0.2', protocol: 6, payloadLength: 10 });
  for (let byte = 0; byte < 20; byte++) {
    for (let bit = 0; bit < 8; bit++) {
      const c = h.slice();
      c[byte] ^= 1 << bit;
      assert.equal(verifyIPv4Checksum(c), false, `byte ${byte} bit ${bit}`);
    }
  }
});

test('parse rejects truncated, non-IPv4 and optioned headers', () => {
  assert.equal(parseIPv4(new Uint8Array(10)).valid, false);
  const h = buildIPv4Header({ src: '1.1.1.1', dst: '2.2.2.2', protocol: 1, payloadLength: 0 });
  const v6 = h.slice(); v6[0] = 0x65;
  assert.equal(parseIPv4(v6).valid, false);
  const opts = h.slice(); opts[0] = 0x46;
  assert.equal(parseIPv4(opts).valid, false);
});

test('builder rejects invalid input', () => {
  assert.throws(() => buildIPv4Header({ src: '300.1.1.1', dst: '1.1.1.1', protocol: 1, payloadLength: 0 }), SimError);
  assert.throws(() => buildIPv4Header({ src: '1.1.1', dst: '1.1.1.1', protocol: 1, payloadLength: 0 }), SimError);
  assert.throws(() => buildIPv4Header({ src: '1.1.1.1', dst: '1.1.1.1', protocol: 999, payloadLength: 0 }), SimError);
  assert.throws(() => buildIPv4Header({ src: '1.1.1.1', dst: '1.1.1.1', protocol: 1, payloadLength: 70000 }), SimError);
  assert.throws(() => buildIPv4Header({ src: '1.1.1.1', dst: '1.1.1.1', protocol: 1, payloadLength: 0, ttl: 256 }), SimError);
});

test('makePlainPacket = IPv4 header + application payload (protocol 253, not TCP)', () => {
  const p = makePlainPacket({ src: '192.168.1.10', dst: '192.168.2.20', payload: encoder.encode('hello') });
  const ip = parseIPv4(p);
  assert.equal(p.length, 25);
  assert.equal(ip.protocol, 253);
  assert.equal(ip.totalLength, 25);
  assert.equal(new TextDecoder().decode(p.slice(20)), 'hello');
});

test('router forwarding decrements TTL and recomputes the checksum', () => {
  const p = makePlainPacket({ src: '10.0.0.1', dst: '10.0.0.2', payload: encoder.encode('x'), ttl: 64 });
  const r = routerForward(p);
  assert.equal(r.ok, true);
  assert.equal(r.ttl, 63);
  const ip = parseIPv4(r.packet);
  assert.equal(ip.ttl, 63);
  assert.equal(ip.checksumValid, true);
});

test('router drops expired TTL and corrupted headers', () => {
  const p = makePlainPacket({ src: '10.0.0.1', dst: '10.0.0.2', payload: encoder.encode('x'), ttl: 1 });
  const r = routerForward(p);
  assert.equal(r.ok, false);
  assert.match(r.reason, /TTL expired/);
  const q = makePlainPacket({ src: '10.0.0.1', dst: '10.0.0.2', payload: encoder.encode('x') });
  q[12] ^= 1; // corrupt without fixing the checksum
  const r2 = routerForward(q);
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /checksum/);
});

test('rewriteIPv4 changes fields and keeps the checksum valid', () => {
  const p = makePlainPacket({ src: '10.0.0.1', dst: '10.0.0.2', payload: encoder.encode('x') });
  const q = rewriteIPv4(p, { src: '10.10.10.10', ttl: 10 });
  const ip = parseIPv4(q);
  assert.equal(ip.src, '10.10.10.10');
  assert.equal(ip.ttl, 10);
  assert.equal(ip.checksumValid, true);
  assert.equal(toHex(q.slice(20)), toHex(p.slice(20)));
});

test('AH mutable fields: TOS, flags, fragment offset, TTL and checksum are zeroed; the rest is kept', () => {
  assert.deepEqual([...MUTABLE_FIELDS], ['TOS', 'Flags', 'Fragment offset', 'TTL', 'Header checksum']);
  const h = buildIPv4Header({ src: '192.168.1.10', dst: '192.168.2.20', protocol: 51, payloadLength: 50, ttl: 64, tos: 0x28, id: 0x1234 });
  const z = zeroMutableFields(h);
  assert.equal(z[1], 0);
  assert.equal(z[6], 0);
  assert.equal(z[7], 0);
  assert.equal(z[8], 0);
  assert.equal(z[10], 0);
  assert.equal(z[11], 0);
  for (const i of [0, 2, 3, 4, 5, 9, 12, 13, 14, 15, 16, 17, 18, 19]) assert.equal(z[i], h[i], `byte ${i} must be unchanged`);
  // the same zeroed form results after a router changed TTL/checksum
  const after = rewriteIPv4(h, { ttl: 61 });
  assert.equal(toHex(zeroMutableFields(after)), toHex(z));
});
