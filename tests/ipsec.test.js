// AH / ESP packet construction and receiver verification (engine/ipsec.js).

import test from 'node:test';
import assert from 'node:assert/strict';
import { protect, processInbound, AH_LEN, AH_LEN_FIELD } from '../src/engine/ipsec.js';
import { parseIPv4, rewriteIPv4, makePlainPacket, PROTO } from '../src/engine/ipv4.js';
import { decoder, encoder, toHex, indexOfBytes, SimError, r32 } from '../src/engine/bytes.js';
import { SecurityAssociationDatabase } from '../src/engine/sa.js';
import { aesCbcDecrypt } from '../src/engine/crypto.js';
import {
  COMBOS, setup, send, plain, MESSAGE, HOST_A, HOST_B, GW_A, GW_B,
} from './helpers.js';

const text = (r) => decoder.decode(r.payload);

test('every protocol x mode combination: sender output is accepted and the payload recovered', async () => {
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    const r = await processInbound(wire, ctx.endpoint);
    assert.equal(r.accepted, true, `${prot}/${mode}: ${r.reason}`);
    assert.equal(text(r), MESSAGE);
    const d = parseIPv4(r.delivered);
    assert.equal(d.src, HOST_A);
    assert.equal(d.dst, HOST_B);
    assert.equal(d.checksumValid, true);
  }
});

test('packet sizes and the IP protocol field for the 34-byte message', async () => {
  const expected = { // [protocol, mode] -> [overhead, outer protocol]
    'AH/transport': [28, 51], 'AH/tunnel': [48, 51],
    'ESP/transport': [54, 50], 'ESP/tunnel': [70, 50],
    'AH_ESP/transport': [82, 51], 'AH_ESP/tunnel': [98, 51],
  };
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const original = plain();
    const { wire } = await send(ctx, original);
    const [overhead, outerProto] = expected[`${prot}/${mode}`];
    assert.equal(wire.length - original.length, overhead, `${prot}/${mode} overhead`);
    assert.equal(parseIPv4(wire).protocol, outerProto, `${prot}/${mode} protocol field`);
    assert.equal(parseIPv4(wire).totalLength, wire.length);
    assert.equal(parseIPv4(wire).checksumValid, true);
  }
});

test('AH header layout: next header, payload length 5, reserved 0, SPI, sequence, 16-byte ICV', async () => {
  const ctx = await setup('AH', 'transport');
  const { wire } = await send(ctx);
  const ah = wire.subarray(20, 20 + AH_LEN);
  assert.equal(AH_LEN, 28);
  assert.equal(AH_LEN_FIELD, 5);
  assert.equal(ah[0], PROTO.APP); // next header = the hidden application protocol
  assert.equal(ah[1], 5);
  assert.equal(ah[2] | ah[3], 0);
  assert.equal(r32(ah, 4), ctx.sas.ah.spi);
  assert.equal(r32(ah, 8), 1);
  assert.equal(wire.length, 20 + 28 + 34);
});

test('AH does not encrypt; ESP does (payload visible on the wire or not)', async () => {
  const msg = encoder.encode(MESSAGE);
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    const visible = indexOfBytes(wire, msg) >= 0;
    assert.equal(visible, prot === 'AH', `${prot}/${mode}`);
  }
});

test('ESP tunnel hides the original IP header; AH tunnel does not', async () => {
  const hdr = plain().slice(12, 20); // original src+dst bytes
  const esp = await setup('ESP', 'tunnel');
  assert.equal(indexOfBytes((await send(esp)).wire.subarray(20), hdr), -1);
  const ah = await setup('AH', 'tunnel');
  assert.ok(indexOfBytes((await send(ah)).wire.subarray(20), hdr) >= 0);
  const ahTransport = await setup('AH', 'transport');
  assert.equal(parseIPv4((await send(ahTransport)).wire).src, HOST_A); // transport keeps host addresses
});

test('tunnel mode adds a new outer header between the gateways; transport keeps the host addresses', async () => {
  for (const prot of ['AH', 'ESP', 'AH_ESP']) {
    const t = await setup(prot, 'tunnel');
    const o = parseIPv4((await send(t)).wire);
    assert.equal(o.src, GW_A);
    assert.equal(o.dst, GW_B);
    const p = await setup(prot, 'transport');
    const q = parseIPv4((await send(p)).wire);
    assert.equal(q.src, HOST_A);
    assert.equal(q.dst, HOST_B);
  }
});

test('ESP trailer: padding is 1,2,3..., pad length and next header are correct, block-aligned', async () => {
  for (const len of [1, 5, 13, 14, 15, 16, 17, 34, 100]) {
    const ctx = await setup('ESP', 'transport');
    const msg = 'x'.repeat(len);
    const { wire } = await send(ctx, plain(msg));
    const iv = wire.subarray(28, 44);
    const ct = wire.subarray(44, wire.length - 16);
    assert.equal(ct.length % 16, 0);
    const pt = await aesCbcDecrypt(ctx.sas.esp.encKey, iv, ct);
    const padLen = pt[pt.length - 2];
    assert.equal(pt[pt.length - 1], PROTO.APP);
    assert.equal(padLen, (16 - ((len + 2) % 16)) % 16);
    for (let i = 0; i < padLen; i++) assert.equal(pt[len + i], i + 1);
    assert.equal(decoder.decode(pt.subarray(0, len)), msg);
  }
});

test('AH: every byte of the packet is protected except the mutable IP fields', async () => {
  for (const mode of ['transport', 'tunnel']) {
    const ctx = await setup('AH', mode);
    const { wire } = await send(ctx);
    for (let i = 0; i < wire.length; i++) {
      ctx.endpoint.sad.all().forEach((sa) => sa.replay.reset()); // isolate each attempt from the replay window
      const w = wire.slice();
      w[i] ^= 0x01;
      if (i < 20) {
        // header bytes: re-fix the checksum so the router-valid header isolates the ICV check
        if (i === 10 || i === 11) continue;
        const f = rewriteIPv4(w, {});
        const r = await processInbound(f, ctx.endpoint);
        const mutable = [1, 6, 7, 8].includes(i);
        assert.equal(r.accepted, mutable, `AH/${mode} header byte ${i} should be ${mutable ? 'accepted (mutable)' : 'rejected'}`);
      } else {
        const r = await processInbound(w, ctx.endpoint);
        assert.equal(r.accepted, false, `AH/${mode} byte ${i}`);
        if (i >= 20 + AH_LEN) {
          // payload / inner packet: only the ICV can notice the change
          assert.equal(r.droppedAt, 'ICV verification', `AH/${mode} byte ${i} dropped at ${r.droppedAt}`);
        } else {
          // AH header bytes (next header, length, SPI, sequence, ICV): refused at parsing, SA lookup, replay or ICV
          assert.ok(['Protocol parsing', 'SA lookup', 'Anti-replay check', 'ICV verification'].includes(r.droppedAt), `AH/${mode} byte ${i}: ${r.droppedAt}`);
        }
      }
    }
  }
});

test('ESP and AH+ESP: any single-bit change after the IP header is rejected', async () => {
  for (const prot of ['ESP', 'AH_ESP']) {
    for (const mode of ['transport', 'tunnel']) {
      const ctx = await setup(prot, mode);
      const { wire } = await send(ctx);
      for (let i = 20; i < wire.length; i++) {
        const w = wire.slice();
        w[i] ^= 0x01;
        const r = await processInbound(w, ctx.endpoint);
        assert.equal(r.accepted, false, `${prot}/${mode} byte ${i}`);
      }
    }
  }
});

test('IP header fields: AH detects source/destination/ID changes (checksum fixed); ESP does not cover the header', async () => {
  const ah = await setup('AH', 'transport');
  const awire = (await send(ah)).wire;
  for (const patch of [{ src: '10.10.10.10' }, { dst: '10.9.9.9' }]) {
    const r = await processInbound(rewriteIPv4(awire, patch), ah.endpoint);
    assert.equal(r.accepted, false);
    assert.equal(r.droppedAt, 'ICV verification');
  }
  const esp = await setup('ESP', 'transport');
  const ewire = (await send(esp)).wire;
  const r = await processInbound(rewriteIPv4(ewire, { src: '10.10.10.10' }), esp.endpoint);
  assert.equal(r.accepted, true, 'ESP ICV does not cover the IP header');
  assert.equal(parseIPv4(r.delivered).src, '10.10.10.10');
});

test('mutable fields: TTL / TOS changes with a fixed checksum do not break AH or ESP', async () => {
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    const r = await processInbound(rewriteIPv4(wire, { ttl: 40, tos: 0x28 }), ctx.endpoint);
    assert.equal(r.accepted, true, `${prot}/${mode}: ${r.reason}`);
  }
});

test('a wrong IPv4 checksum is rejected before any IPsec processing', async () => {
  const ctx = await setup('AH', 'transport');
  const { wire } = await send(ctx);
  const w = wire.slice();
  w[8] ^= 0x01; // TTL changed without fixing the checksum
  const r = await processInbound(w, ctx.endpoint);
  assert.equal(r.accepted, false);
  assert.equal(r.droppedAt, 'IPv4 validation');
});

test('replay: a duplicate is rejected by the anti-replay check', async () => {
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    assert.equal((await processInbound(wire, ctx.endpoint)).accepted, true);
    const second = await processInbound(wire, ctx.endpoint);
    assert.equal(second.accepted, false);
    assert.equal(second.droppedAt, 'Anti-replay check');
    assert.match(second.reason, /REPLAY DETECTED/);
  }
});

test('replay state is only updated after authentication succeeds', async () => {
  const ctx = await setup('ESP', 'transport');
  const { wire } = await send(ctx);
  const bad = wire.slice();
  bad[bad.length - 1] ^= 0x01; // corrupt the ICV, sequence number stays 1
  const r1 = await processInbound(bad, ctx.endpoint);
  assert.equal(r1.droppedAt, 'ICV verification');
  assert.equal(ctx.endpoint.sad.all()[0].replay.highest, 0, 'a failed ICV must not move the window');
  const r2 = await processInbound(wire, ctx.endpoint); // the genuine packet with the same sequence still works
  assert.equal(r2.accepted, true);
  assert.equal(ctx.endpoint.sad.all()[0].replay.highest, 1);
});

test('sequence numbers increase 1,2,3... per SA and out-of-order delivery within the window works', async () => {
  const ctx = await setup('AH', 'transport');
  const w = [];
  for (let i = 0; i < 5; i++) w.push((await send(ctx)).wire);
  assert.deepEqual(w.map((x) => r32(x, 28)), [1, 2, 3, 4, 5]);
  for (const i of [4, 2, 0, 3, 1]) assert.equal((await processInbound(w[i], ctx.endpoint)).accepted, true, `seq ${i + 1}`);
  for (const i of [0, 1, 2, 3, 4]) assert.equal((await processInbound(w[i], ctx.endpoint)).accepted, false);
});

test('packets older than the 32-packet window are rejected', async () => {
  const ctx = await setup('ESP', 'transport');
  const first = (await send(ctx)).wire;
  let last;
  for (let i = 0; i < 40; i++) last = (await send(ctx)).wire;
  assert.equal((await processInbound(last, ctx.endpoint)).accepted, true);
  const r = await processInbound(first, ctx.endpoint);
  assert.equal(r.accepted, false);
  assert.match(r.reason, /older than the 32-packet window/);
});

test('forgery with invented keys is rejected at the ICV check (SPI and sequence copied)', async () => {
  for (const [prot, mode] of COMBOS) {
    const real = await setup(prot, mode);
    const other = await setup(prot, mode); // different random keys
    // give the attacker's SAs the victim's SPIs
    for (const k of Object.keys(other.sas)) { other.sas[k].spi = real.sas[k].spi; }
    const { wire } = await send(other, plain('FORGED'));
    const r = await processInbound(wire, real.endpoint);
    assert.equal(r.accepted, false, `${prot}/${mode}`);
    assert.equal(r.droppedAt, 'ICV verification');
  }
});

test('unknown SPI is rejected at SA lookup', async () => {
  for (const prot of ['AH', 'ESP']) {
    const real = await setup(prot, 'transport');
    const other = await setup(prot, 'transport');
    const { wire } = await send(other);
    const r = await processInbound(wire, real.endpoint);
    assert.equal(r.accepted, false);
    assert.equal(r.droppedAt, 'SA lookup');
    assert.match(r.reason, /No inbound/);
  }
});

test('SA lookup uses the SPI AND the protocol', async () => {
  const ctx = await setup('AH_ESP', 'transport');
  const { ah, esp } = ctx.sas;
  assert.notEqual(ah.spi, esp.spi);
  assert.equal(ctx.endpoint.sad.lookup(ah.spi, 'AH').protocol, 'AH');
  assert.equal(ctx.endpoint.sad.lookup(ah.spi, 'ESP'), null);
  assert.equal(ctx.endpoint.sad.lookup(esp.spi, 'ESP').protocol, 'ESP');
  assert.equal(ctx.endpoint.sad.lookup(0xdeadbeef, 'ESP'), null);
});

test('receiver uses the packet, not the sender setup: protection is read from the bytes', async () => {
  // Same receiver SAD, packets built by different senders: each is processed according to its own headers.
  const ctx = await setup('AH_ESP', 'transport');
  const both = (await send(ctx)).wire;
  const rb = await processInbound(both, ctx.endpoint);
  assert.equal(rb.accepted, true);
  assert.deepEqual(rb.applied, { ah: true, esp: true, tunnel: false });
  assert.ok(rb.checks.ah && rb.checks.esp);
  const t = await setup('ESP', 'tunnel');
  const rt = await processInbound((await send(t)).wire, t.endpoint);
  assert.deepEqual(rt.applied, { ah: false, esp: true, tunnel: true });
});

test('policy: an unprotected packet is rejected when IPsec is required', async () => {
  for (const [prot, mode] of COMBOS) {
    const ctx = await setup(prot, mode);
    const r = await processInbound(plain(), ctx.endpoint);
    assert.equal(r.accepted, false, `${prot}/${mode}`);
    assert.equal(r.droppedAt, 'Policy check');
  }
});

test('policy: ESP traffic is rejected when the policy demands AH, and tunnel traffic when it demands transport', async () => {
  const esp = await setup('ESP', 'transport');
  const wire = (await send(esp)).wire;
  const demandAh = { ...esp.endpoint, policy: { protection: 'AH', mode: 'transport' } };
  const r = await processInbound(wire, demandAh);
  assert.equal(r.accepted, false);
  assert.equal(r.droppedAt, 'Policy check');
  const tun = await setup('ESP', 'tunnel');
  const demandTransport = { ...tun.endpoint, policy: { protection: 'ESP', mode: 'transport' } };
  const r2 = await processInbound((await send(tun)).wire, demandTransport);
  assert.equal(r2.accepted, false);
  assert.match(r2.reason, /transport mode required/);
});

test('No IPsec policy: an unprotected packet is delivered unchanged', async () => {
  const endpoint = { name: 'Host B', sad: new SecurityAssociationDatabase(), policy: { protection: 'NONE', mode: 'transport' }, strictSelector: false };
  const p = plain();
  const r = await processInbound(p, endpoint);
  assert.equal(r.accepted, true);
  assert.equal(text(r), MESSAGE);
  assert.equal(toHex(r.delivered), toHex(p));
  const t = await protect({ packet: p, protection: 'NONE', mode: 'transport' });
  assert.equal(toHex(t.wire), toHex(p));
});

test('strict selector check: a spoofed source is rejected even under ESP (and a genuine one is accepted)', async () => {
  for (const mode of ['transport', 'tunnel']) {
    const ctx = await setup('ESP', mode, { strictSelector: true });
    const { wire } = await send(ctx);
    assert.equal((await processInbound(wire, ctx.endpoint)).accepted, true);
    const ctx2 = await setup('ESP', mode, { strictSelector: true });
    const w2 = rewriteIPv4((await send(ctx2)).wire, { src: '10.10.10.10' });
    const r = await processInbound(w2, ctx2.endpoint);
    assert.equal(r.accepted, false, mode);
    assert.equal(r.droppedAt, 'Selector check');
  }
});

test('malformed input never throws: truncated, empty and garbage packets are rejected', async () => {
  const ctx = await setup('AH_ESP', 'tunnel');
  const { wire } = await send(ctx);
  for (let n = 0; n < wire.length; n += 7) {
    const r = await processInbound(wire.slice(0, n), ctx.endpoint);
    assert.equal(r.accepted, false, `truncated to ${n}`);
  }
  const garbage = new Uint8Array(80).fill(0xab);
  assert.equal((await processInbound(garbage, ctx.endpoint)).accepted, false);
  assert.equal((await processInbound(new Uint8Array(0), ctx.endpoint)).accepted, false);
  // right header, trailing junk
  const longer = new Uint8Array(wire.length + 4);
  longer.set(wire);
  assert.equal((await processInbound(longer, ctx.endpoint)).accepted, false);
});

test('protect() rejects invalid input', async () => {
  const ctx = await setup('ESP', 'transport');
  await assert.rejects(protect({ packet: plain(), protection: 'XYZ', mode: 'transport', sas: ctx.sas }), SimError);
  await assert.rejects(protect({ packet: plain(), protection: 'ESP', mode: 'sideways', sas: ctx.sas }), SimError);
  await assert.rejects(protect({ packet: plain(), protection: 'ESP', mode: 'transport', sas: {} }), /No outbound ESP SA/);
  await assert.rejects(protect({ packet: plain(), protection: 'AH', mode: 'transport', sas: ctx.sas }), /No outbound AH SA/);
  await assert.rejects(protect({ packet: plain(), protection: 'ESP', mode: 'tunnel', sas: ctx.sas, tunnel: { src: GW_A, dst: GW_B } }), /SA is for transport mode/);
  const t = await setup('ESP', 'tunnel');
  await assert.rejects(protect({ packet: plain(), protection: 'ESP', mode: 'tunnel', sas: t.sas }), /outer \(gateway\) addresses/);
  await assert.rejects(protect({ packet: new Uint8Array(5), protection: 'ESP', mode: 'transport', sas: ctx.sas }), SimError);
});

test('sequence number exhaustion forces a new SA', async () => {
  const ctx = await setup('ESP', 'transport');
  ctx.sas.esp.txSeq = 0xfffffffe;
  assert.equal(ctx.sas.esp.nextSeq(), 0xffffffff);
  assert.throws(() => ctx.sas.esp.nextSeq(), /exhausted/);
  assert.equal(ctx.sas.esp.state, 'EXPIRED');
  await assert.rejects(send(ctx));
});

test('decrypted payload is only produced after the ICV passes (no plaintext for a tampered ESP packet)', async () => {
  const ctx = await setup('ESP', 'transport');
  const { wire } = await send(ctx);
  const w = wire.slice();
  w[40] ^= 0x01;
  const r = await processInbound(w, ctx.endpoint);
  assert.equal(r.accepted, false);
  assert.equal(r.plaintext, null);
  assert.equal(r.checks.esp.decrypt, 'not-evaluated');
});
