// End-to-end scenarios through the Simulator (network, attacker, receiver, status).

import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulator, normalizeConfig, DEFAULT_CONFIG, INTERNET_HOPS, GATEWAY_A_IP, GATEWAY_B_IP } from '../src/engine/simulator.js';
import { parseIPv4 } from '../src/engine/ipv4.js';
import { SimError } from '../src/engine/bytes.js';
import { FORGED_TEXT } from '../src/engine/attacker.js';

const run = (cfg, sim = new Simulator()) => sim.run(cfg);
const SECURED = [['AH', 'transport'], ['AH', 'tunnel'], ['ESP', 'transport'], ['ESP', 'tunnel'], ['AH_ESP', 'transport'], ['AH_ESP', 'tunnel']];

test('config validation rejects bad input', async () => {
  const bad = [
    { protection: 'IPSEC' }, { mode: 'bridge' }, { attack: 'ddos' },
    { srcIp: '999.1.1.1' }, { dstIp: 'not-an-ip' }, { srcIp: '1.1.1.1', dstIp: '1.1.1.1' },
    { payload: '' }, { payload: 'x'.repeat(201) }, { attack: 'spoof', spoofIp: '1.2.3' },
  ];
  for (const b of bad) await assert.rejects(run(b), SimError, JSON.stringify(b));
  assert.equal(normalizeConfig({}).protection, DEFAULT_CONFIG.protection);
  assert.equal(normalizeConfig({ strictSelector: 1 }).strictSelector, true);
});

test('normal delivery for every combination: accepted, payload intact, all statuses verified', async () => {
  for (const [protection, mode] of SECURED) {
    const r = await run({ protection, mode });
    const t = r.primary;
    assert.equal(t.accepted, true, `${protection}/${mode}`);
    assert.equal(t.delivery.text, DEFAULT_CONFIG.payload);
    assert.equal(t.delivery.matchesOriginal, true);
    assert.equal(t.dropped, null);
    assert.equal(t.status.authentication.state, 'verified');
    assert.equal(t.status.integrity.state, 'verified');
    assert.equal(t.status.antiReplay.state, 'verified');
    assert.equal(t.status.packet.label, 'ACCEPTED');
    assert.equal(t.status.confidentiality.state, protection === 'AH' ? 'not-provided' : 'verified');
  }
});

test('No IPsec baseline: delivered, but nothing is provided', async () => {
  const r = await run({ protection: 'NONE' });
  const t = r.primary;
  assert.equal(t.accepted, true);
  assert.equal(r.secured, false);
  assert.equal(r.sas.length, 0);
  assert.equal(t.atAttacker.exposure.payloadReadable, true);
  for (const k of ['confidentiality', 'authentication', 'integrity', 'antiReplay']) assert.equal(t.status[k].state, 'not-provided', k);
  assert.equal(r.overhead, 0);
  assert.deepEqual(r.route, ['hostA', 'internet', 'hostB']);
});

test('No IPsec: every attack succeeds (nothing detects tampering, forgery, replay or spoofing)', async () => {
  const tamper = (await run({ protection: 'NONE', attack: 'tamper' })).primary;
  assert.equal(tamper.accepted, true);
  assert.equal(tamper.outcome, 'succeeded');
  assert.notEqual(tamper.delivery.text, DEFAULT_CONFIG.payload);
  const forge = (await run({ protection: 'NONE', attack: 'forge' })).primary;
  assert.equal(forge.accepted, true);
  assert.equal(forge.delivery.text, FORGED_TEXT);
  const spoof = (await run({ protection: 'NONE', attack: 'spoof' })).primary;
  assert.equal(spoof.accepted, true);
  assert.equal(spoof.delivery.src, '10.10.10.10');
  assert.equal(spoof.outcome, 'succeeded');
  const replay = await run({ protection: 'NONE', attack: 'replay' });
  assert.equal(replay.transmissions.length, 2);
  assert.ok(replay.transmissions.every((t) => t.accepted), 'a duplicate is delivered twice');
  assert.equal(replay.primary.outcome, 'succeeded');
});

test('tamper is detected by AH, ESP and AH+ESP, in both modes', async () => {
  for (const [protection, mode] of SECURED) {
    const t = (await run({ protection, mode, attack: 'tamper' })).primary;
    assert.equal(t.accepted, false, `${protection}/${mode}`);
    assert.equal(t.outcome, 'defended');
    assert.equal(t.dropped.stage, 'ICV verification');
    assert.equal(t.status.integrity.state, 'failed');
    assert.equal(t.status.authentication.state, 'failed');
    assert.equal(t.delivery, null, 'nothing reaches the application');
    assert.ok(t.atAttacker.changes.length === 1 && t.atAttacker.modified);
  }
});

test('forge is detected (attacker has no keys)', async () => {
  for (const [protection, mode] of SECURED) {
    const t = (await run({ protection, mode, attack: 'forge' })).primary;
    assert.equal(t.accepted, false, `${protection}/${mode}`);
    assert.equal(t.dropped.stage, 'ICV verification');
    assert.equal(t.outcome, 'defended');
  }
});

test('replay: first copy accepted, second copy rejected by the anti-replay check', async () => {
  for (const [protection, mode] of SECURED) {
    const r = await run({ protection, mode, attack: 'replay' });
    assert.equal(r.transmissions.length, 2);
    assert.equal(r.transmissions[0].accepted, true);
    const second = r.transmissions[1];
    assert.equal(second.accepted, false, `${protection}/${mode}`);
    assert.equal(second.injected, true);
    assert.equal(second.dropped.stage, 'Anti-replay check');
    assert.match(second.dropped.reason, /REPLAY DETECTED/);
    assert.equal(second.status.antiReplay.state, 'failed');
    assert.equal(second.status.authentication.state, 'unknown', 'ICV is not evaluated once the replay check fails');
  }
});

test('modify source IP: AH rejects; ESP does not cover the header (transport: delivered with spoofed source)', async () => {
  for (const mode of ['transport', 'tunnel']) {
    const ah = (await run({ protection: 'AH', mode, attack: 'spoof' })).primary;
    assert.equal(ah.accepted, false);
    assert.equal(ah.dropped.stage, 'ICV verification');
    assert.equal(ah.outcome, 'defended');
    const both = (await run({ protection: 'AH_ESP', mode, attack: 'spoof' })).primary;
    assert.equal(both.accepted, false);
  }
  const espT = (await run({ protection: 'ESP', mode: 'transport', attack: 'spoof' })).primary;
  assert.equal(espT.accepted, true);
  assert.equal(espT.delivery.src, '10.10.10.10');
  assert.equal(espT.outcome, 'succeeded');
  const espTun = (await run({ protection: 'ESP', mode: 'tunnel', attack: 'spoof' })).primary;
  assert.equal(espTun.accepted, true);
  assert.equal(espTun.delivery.src, DEFAULT_CONFIG.srcIp, 'tunnel: the authenticated inner header is delivered');
  assert.equal(espTun.outcome, 'no-effect');
});

test('strict selector check makes ESP reject the spoofed source', async () => {
  for (const mode of ['transport', 'tunnel']) {
    const t = (await run({ protection: 'ESP', mode, attack: 'spoof', strictSelector: true })).primary;
    assert.equal(t.accepted, false, mode);
    assert.equal(t.dropped.stage, 'Selector check');
  }
});

test('the attacker shows the changed fields (spoof)', async () => {
  const t = (await run({ protection: 'AH', attack: 'spoof', spoofIp: '10.99.99.99' })).primary;
  const src = t.atAttacker.changes.find((c) => c.field === 'IP source address');
  assert.equal(src.before, DEFAULT_CONFIG.srcIp);
  assert.equal(src.after, '10.99.99.99');
  assert.equal(parseIPv4(t.atAttacker.modified).src, '10.99.99.99');
  assert.equal(parseIPv4(t.atAttacker.modified).checksumValid, true, 'attacker fixes the checksum so routers forward it');
});

test('packets are dropped at the node that verifies them', async () => {
  for (const [protection, mode] of SECURED) {
    const t = (await run({ protection, mode, attack: 'tamper' })).primary;
    assert.equal(t.droppedNode, mode === 'tunnel' ? 'gwB' : 'hostB', `${protection}/${mode}`);
    const last = t.frames[t.frames.length - 1];
    assert.equal(last.node, t.droppedNode);
    assert.equal(last.state, 'bad');
    assert.ok(!t.frames.some((f) => f.node === 'hostB' && mode === 'tunnel'), 'a rejected tunnel packet never reaches Host B');
  }
});

test('routes: transport has no gateways, tunnel has Gateway A and B', async () => {
  assert.deepEqual((await run({ protection: 'ESP', mode: 'transport' })).route, ['hostA', 'internet', 'hostB']);
  assert.deepEqual((await run({ protection: 'ESP', mode: 'tunnel' })).route, ['hostA', 'gwA', 'internet', 'gwB', 'hostB']);
});

test('TTL: decremented by every router, outer and inner TTLs are tracked separately in tunnel mode', async () => {
  const t = (await run({ protection: 'ESP', mode: 'transport' })).primary;
  assert.equal(parseIPv4(t.sent).ttl, 64);
  assert.equal(parseIPv4(t.arrived).ttl, 64 - INTERNET_HOPS);
  assert.equal(t.delivery.ttl, 64 - INTERNET_HOPS);
  const u = (await run({ protection: 'AH', mode: 'tunnel' })).primary;
  assert.equal(parseIPv4(u.sent).ttl, 64);
  assert.equal(parseIPv4(u.arrived).ttl, 64 - INTERNET_HOPS);
  assert.equal(u.delivery.ttl, 62, 'inner TTL: 64 -1 (Gateway A) -1 (Gateway B)');
  assert.equal(parseIPv4(u.sent).src, GATEWAY_A_IP);
  assert.equal(parseIPv4(u.sent).dst, GATEWAY_B_IP);
});

test('exposure: ESP hides the payload and (tunnel) the original addresses; AH hides nothing', async () => {
  const exp = async (protection, mode) => (await run({ protection, mode, attack: 'sniff' })).primary.atAttacker.exposure;
  assert.equal((await exp('NONE', 'transport')).payloadReadable, true);
  assert.equal((await exp('AH', 'transport')).payloadReadable, true);
  assert.equal((await exp('ESP', 'transport')).payloadReadable, false);
  assert.equal((await exp('AH_ESP', 'tunnel')).payloadReadable, false);
  assert.equal((await exp('ESP', 'tunnel')).innerAddressesReadable, false);
  assert.equal((await exp('AH', 'tunnel')).innerAddressesReadable, true);
  assert.equal((await exp('ESP', 'transport')).innerAddressesReadable, null);
});

test('AH and ESP use separate SAs with separate SPIs and keys', async () => {
  const r = await run({ protection: 'AH_ESP', mode: 'transport' });
  assert.equal(r.sas.length, 2);
  const [a, e] = [r.sas.find((s) => s.protocol === 'AH'), r.sas.find((s) => s.protocol === 'ESP')];
  assert.notEqual(a.spi, e.spi);
  assert.notEqual(a.authKey, e.authKey);
  assert.equal(a.encKey, null);
  assert.equal(e.encKey.length, 32);
  assert.equal(a.txSeq, 1);
  assert.equal(e.txSeq, 1);
  assert.equal(a.rxHighest, 1);
});

test('SAs persist between packets: sequence numbers continue, no new establishment', async () => {
  const sim = new Simulator();
  const a = await sim.run({ protection: 'ESP', mode: 'transport' });
  const b = await sim.run({ protection: 'ESP', mode: 'transport' });
  assert.ok(a.establishment);
  assert.equal(b.establishment, null);
  assert.equal(b.sas[0].spi, a.sas[0].spi);
  assert.equal(b.primary.receive.seqs.esp, 2);
  assert.equal(b.packetNo, 2);
  assert.equal(b.sas[0].rxHighest, 2);
});

test('switching protection reuses existing SAs and only creates the missing ones', async () => {
  const sim = new Simulator();
  const ah = await sim.run({ protection: 'AH', mode: 'transport' });
  const both = await sim.run({ protection: 'AH_ESP', mode: 'transport' });
  assert.deepEqual(both.establishment.protection, 'ESP');
  assert.equal(both.sas.length, 2);
  assert.equal(both.sas.find((s) => s.protocol === 'AH').spi, ah.sas[0].spi);
  const tunnel = await sim.run({ protection: 'AH', mode: 'tunnel' }); // different mode = different SA
  assert.ok(tunnel.establishment);
  assert.equal(tunnel.sas.length, 3);
});

test('reset clears SAs, replay state and the packet counter; rekey issues new SPIs', async () => {
  const sim = new Simulator();
  const a = await sim.run({ protection: 'AH', mode: 'transport' });
  const a2 = await sim.run({ protection: 'AH', mode: 'transport' });
  assert.equal(a2.packetNo, 2);
  sim.rekey();
  const b = await sim.run({ protection: 'AH', mode: 'transport' });
  assert.ok(b.establishment);
  assert.notEqual(b.sas[0].spi, a.sas[0].spi);
  assert.equal(b.primary.receive.seqs.ah, 1, 'new SA starts at sequence 1');
  sim.reset();
  assert.equal(sim.counter, 0);
  assert.equal(sim.describeSAs().length, 0);
  const c = await sim.run({ protection: 'AH', mode: 'transport' });
  assert.equal(c.packetNo, 1);
  assert.equal(c.primary.accepted, true);
});

test('a captured packet from before a rekey is not accepted afterwards', async () => {
  const sim = new Simulator();
  const first = await sim.run({ protection: 'ESP', mode: 'transport' });
  const oldWire = first.primary.sent;
  sim.rekey();
  await sim.run({ protection: 'ESP', mode: 'transport' });
  const { processInbound } = await import('../src/engine/ipsec.js');
  const r = await processInbound(oldWire, { name: 'Host B', sad: sim.rxSad, policy: { protection: 'ESP', mode: 'transport' }, strictSelector: false });
  assert.equal(r.accepted, false);
  assert.equal(r.droppedAt, 'SA lookup');
});

test('event log tells the story in order', async () => {
  const r = await run({ protection: 'ESP', mode: 'transport' });
  const text = r.log.map((l) => l.text).join('\n');
  const order = [
    'Packet created', 'IPsec processing started', 'SA selected: ESP', 'ESP encryption completed', 'ESP authentication generated',
    'Packet transmitted', 'captured the packet', 'forwarded by 3 routers', 'Packet received at Host B',
    'Locate Security Association (ESP)', 'Anti-replay check (ESP)', 'Verify ESP Integrity Check Value', 'Update replay window (ESP)', 'Decrypt ESP payload', 'PACKET ACCEPTED',
  ];
  let pos = -1;
  for (const frag of order) {
    const i = text.indexOf(frag);
    assert.ok(i > pos, `"${frag}" missing or out of order`);
    pos = i;
  }
  assert.deepEqual(r.log.map((l) => l.n), r.log.map((_, i) => i + 1));
});

test('views: before / after / attacker / receiver dissections exist and reflect the real bytes', async () => {
  const r = await run({ protection: 'ESP', mode: 'tunnel', attack: 'tamper' });
  const t = r.primary;
  assert.equal(r.original.view.layers.map((l) => l.kind).join(), 'ip,payload');
  assert.ok(t.views.after.layers.some((l) => l.kind === 'ciphertext'));
  assert.ok(t.views.attackerModified);
  assert.equal(t.views.receiver.layers.some((l) => l.inside), false, 'a rejected packet is never decrypted');
  const ok = (await run({ protection: 'ESP', mode: 'tunnel' })).primary;
  assert.ok(ok.views.receiver.layers.some((l) => l.id === 'inner-ip' && l.inside));
});
