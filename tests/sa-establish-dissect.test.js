// SA database, simplified SA establishment, dissector, status and capability claims.

import test from 'node:test';
import assert from 'node:assert/strict';
import { SecurityAssociation, SecurityAssociationDatabase, requiredProtocols, PROTECTIONS } from '../src/engine/sa.js';
import { establishSAs } from '../src/engine/establish.js';
import { dissect } from '../src/engine/dissect.js';
import { computeStatus, headerCoverage } from '../src/engine/status.js';
import { CAPABILITIES, COLUMNS } from '../src/engine/capabilities.js';
import { runMatrix } from '../src/engine/matrix.js';
import { processInbound } from '../src/engine/ipsec.js';
import { randomBytes, SimError, toHex } from '../src/engine/bytes.js';
import { setup, send, plain, HOST_A, HOST_B, GW_A, GW_B, MESSAGE } from './helpers.js';

const mk = (over = {}) =>
  new SecurityAssociation({
    protocol: 'ESP', spi: 0x1000, mode: 'transport', authKey: randomBytes(32), encKey: randomBytes(16),
    peerSrc: HOST_A, peerDst: HOST_B, trafficSrc: HOST_A, trafficDst: HOST_B, ...over,
  });

test('SA validation', () => {
  assert.throws(() => mk({ protocol: 'IPCOMP' }), SimError);
  assert.throws(() => mk({ spi: 100 }), /reserved/);
  assert.throws(() => mk({ spi: 2 ** 32 }), SimError);
  assert.throws(() => mk({ authKey: randomBytes(16) }), SimError);
  assert.throws(() => mk({ encKey: null }), SimError);
  assert.throws(() => mk({ mode: 'bridge' }), SimError);
  assert.equal(mk({ protocol: 'AH', encKey: null }).encAlg, null);
  assert.equal(mk().encAlg, 'AES-128-CBC');
});

test('SA database: lookup by SPI + protocol, duplicates refused, clear', () => {
  const db = new SecurityAssociationDatabase();
  const a = db.add(mk());
  assert.equal(db.lookup(0x1000, 'ESP'), a);
  assert.equal(db.lookup(0x1000, 'AH'), null);
  assert.throws(() => db.add(mk()), /already exists/);
  db.add(mk({ protocol: 'AH', encKey: null })); // same SPI, other protocol: allowed
  assert.equal(db.all().length, 2);
  assert.equal(db.find({ protocol: 'ESP', mode: 'transport', trafficSrc: HOST_A, trafficDst: HOST_B }), a);
  assert.equal(db.find({ protocol: 'ESP', mode: 'tunnel', trafficSrc: HOST_A, trafficDst: HOST_B }), null);
  a.state = 'EXPIRED';
  assert.equal(db.lookup(0x1000, 'ESP'), null, 'inactive SAs are not used');
  db.clear();
  assert.equal(db.all().length, 0);
});

test('requiredProtocols', () => {
  assert.deepEqual(requiredProtocols('NONE'), { ah: false, esp: false });
  assert.deepEqual(requiredProtocols('AH'), { ah: true, esp: false });
  assert.deepEqual(requiredProtocols('ESP'), { ah: false, esp: true });
  assert.deepEqual(requiredProtocols('AH_ESP'), { ah: true, esp: true });
  assert.throws(() => requiredProtocols('GRE'), SimError);
  assert.deepEqual([...PROTECTIONS], ['NONE', 'AH', 'ESP', 'AH_ESP']);
});

test('SA establishment: separate AH and ESP SAs, matching keys on both ends, unique SPIs, real steps', async () => {
  const taken = new Set();
  const est = await establishSAs({
    protection: 'AH_ESP', mode: 'tunnel', hostSrc: HOST_A, hostDst: HOST_B, gwSrc: GW_A, gwDst: GW_B, psk: randomBytes(32), takenSpis: taken,
  });
  assert.deepEqual(Object.keys(est.tx).sort(), ['ah', 'esp']);
  assert.notEqual(est.tx.ah.spi, est.tx.esp.spi);
  assert.notEqual(toHex(est.tx.ah.authKey), toHex(est.tx.esp.authKey));
  for (const k of ['ah', 'esp']) {
    assert.equal(toHex(est.tx[k].authKey), toHex(est.rx[k].authKey), `${k} keys agree on both ends`);
    assert.equal(est.tx[k].spi, est.rx[k].spi);
    assert.equal(est.tx[k].mode, 'tunnel');
    assert.equal(est.tx[k].txSeq, 0);
    assert.equal(est.rx[k].replay.highest, 0);
    assert.equal(est.tx[k].peerSrc, GW_A);
  }
  assert.equal(toHex(est.tx.esp.encKey), toHex(est.rx.esp.encKey));
  assert.equal(taken.size, 2);
  assert.deepEqual(est.steps.map((s) => s.id), ['propose', 'accept', 'dh', 'auth', 'kdf', 'spi', 'sa', 'go']);
});

test('SA establishment is different every time (fresh ECDH, fresh SPIs, fresh keys)', async () => {
  const args = { protection: 'ESP', mode: 'transport', hostSrc: HOST_A, hostDst: HOST_B, gwSrc: GW_A, gwDst: GW_B, psk: randomBytes(32) };
  const a = await establishSAs(args);
  const b = await establishSAs(args);
  assert.notEqual(toHex(a.tx.esp.encKey), toHex(b.tx.esp.encKey));
  assert.notEqual(a.tx.esp.spi, b.tx.esp.spi);
});

test('SA establishment fails when the pre-shared keys differ, and when no SA is needed', async () => {
  const args = { protection: 'ESP', mode: 'transport', hostSrc: HOST_A, hostDst: HOST_B, gwSrc: GW_A, gwDst: GW_B };
  await assert.rejects(establishSAs({ ...args, psk: randomBytes(32), responderPsk: randomBytes(32) }), /pre-shared keys differ/);
  await assert.rejects(establishSAs({ ...args, protection: 'NONE', psk: randomBytes(32) }), /No IPsec/);
});

test('dissector: layer structure for each protection / mode', async () => {
  const kinds = async (prot, mode, opts) => {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    return dissect(wire, opts).layers.map((l) => l.kind).join(',');
  };
  assert.equal(await kinds('AH', 'transport'), 'ip,ah,icv,payload');
  assert.equal(await kinds('AH', 'tunnel'), 'ip,ah,icv,inner-ip,payload');
  assert.equal(await kinds('ESP', 'transport'), 'ip,esp,iv,ciphertext,icv');
  assert.equal(await kinds('ESP', 'tunnel'), 'ip,esp,iv,ciphertext,icv');
  assert.equal(await kinds('AH_ESP', 'transport'), 'ip,ah,icv,esp,iv,ciphertext,icv');
  const ctx = await setup('ESP', 'tunnel');
  const { wire } = await send(ctx);
  const r = await processInbound(wire, ctx.endpoint);
  const full = dissect(wire, { plaintext: r.plaintext }).layers.map((l) => l.kind).join(',');
  assert.equal(full, 'ip,esp,iv,ciphertext,icv,inner-ip,payload,trailer,trailer,trailer');
});

test('dissector: coverage flags (auth / enc) match the protocol', async () => {
  const get = async (prot, mode) => {
    const ctx = await setup(prot, mode);
    return dissect((await send(ctx)).wire).layers;
  };
  let l = await get('AH', 'transport');
  assert.equal(l.find((x) => x.kind === 'ip').auth, 'partial');
  assert.equal(l.find((x) => x.kind === 'payload').auth, 'full');
  assert.equal(l.find((x) => x.kind === 'payload').enc, false);
  l = await get('ESP', 'transport');
  assert.equal(l.find((x) => x.kind === 'ip').auth, 'none');
  assert.equal(l.find((x) => x.kind === 'ciphertext').auth, 'full');
  assert.equal(l.find((x) => x.kind === 'ciphertext').enc, true);
  assert.equal(l.find((x) => x.kind === 'esp').enc, false);
  l = await get('AH_ESP', 'transport');
  assert.equal(l.find((x) => x.kind === 'ip').auth, 'partial');
  // field-level: AH marks the mutable IP fields as zeroed and the rest as authenticated
  const ipFields = (await get('AH', 'transport')).find((x) => x.kind === 'ip').fields;
  assert.equal(ipFields.find((f) => f.label === 'TTL').cov, 'zeroed');
  assert.equal(ipFields.find((f) => f.label === 'Source address').cov, 'auth');
  const espFields = (await get('ESP', 'transport')).find((x) => x.kind === 'ip').fields;
  assert.ok(espFields.every((f) => f.cov === 'none'));
});

test('dissector: layer byte ranges tile the packet exactly and never throw on garbage', async () => {
  for (const [prot, mode] of [['AH', 'transport'], ['ESP', 'tunnel'], ['AH_ESP', 'tunnel']]) {
    const ctx = await setup(prot, mode);
    const { wire } = await send(ctx);
    const d = dissect(wire);
    let pos = 0;
    for (const l of d.layers) { assert.equal(l.offset, pos); pos += l.length; }
    assert.equal(pos, wire.length);
  }
  for (const junk of [new Uint8Array(0), new Uint8Array(5), new Uint8Array(100).fill(0xff), plain().slice(0, 30)]) {
    assert.doesNotThrow(() => dissect(junk));
  }
  assert.equal(dissect(new Uint8Array(3)).ok, false);
});

test('status: derived from the real checks, "unknown" when a stage was never reached', () => {
  const none = computeStatus({ protection: 'NONE', mode: 'transport', exposure: { payloadReadable: true }, receive: null, accepted: true });
  assert.equal(none.confidentiality.state, 'not-provided');
  assert.equal(none.antiReplay.state, 'not-provided');
  const dropped = computeStatus({
    protection: 'ESP', mode: 'transport', exposure: { payloadReadable: false },
    receive: { checks: { esp: { sa: 'fail', icv: 'not-evaluated', replay: 'not-evaluated' } } }, accepted: false,
  });
  assert.equal(dropped.authentication.state, 'unknown');
  assert.equal(dropped.confidentiality.state, 'verified');
  assert.equal(dropped.packet.label, 'REJECTED');
  const leak = computeStatus({ protection: 'ESP', mode: 'transport', exposure: { payloadReadable: true }, receive: null, accepted: false });
  assert.equal(leak.confidentiality.state, 'failed', 'readable payload means confidentiality failed');
  assert.match(headerCoverage('ESP', 'tunnel').text, /Outer IP header is NOT covered/);
  assert.match(headerCoverage('AH', 'transport').text, /immutable/);
  assert.equal(headerCoverage('NONE', 'transport').state, 'not-provided');
});

// ---- The comparison table must say what the simulator actually does ----------------------------

test('capability table agrees with measured behaviour', async () => {
  const rows = await runMatrix();
  const cell = (prot, mode, attack) => rows.find((r) => r.protection === prot && r.mode === mode).cells[attack];
  const claim = (key, col) => CAPABILITIES.find((c) => c.key === key)[col].v;
  assert.deepEqual([...COLUMNS], ['NONE', 'AH', 'ESP', 'AH_ESP']);
  for (const col of COLUMNS) {
    const modes = col === 'NONE' ? ['transport'] : ['transport', 'tunnel'];
    for (const mode of modes) {
      // confidentiality: payload hidden from a sniffer
      assert.equal(!cell(col, mode, 'sniff').payloadReadable, claim('confidentiality', col) === 'yes', `confidentiality ${col}/${mode}`);
      // integrity + authentication: tampering and forgery are rejected
      const defends = cell(col, mode, 'tamper').outcome === 'defended' && cell(col, mode, 'forge').outcome === 'defended';
      assert.equal(defends, claim('integrity', col) === 'yes', `integrity ${col}/${mode}`);
      assert.equal(defends, claim('authentication', col) === 'yes', `authentication ${col}/${mode}`);
      // anti-replay
      assert.equal(cell(col, mode, 'replay').outcome === 'defended', claim('antiReplay', col) === 'yes', `replay ${col}/${mode}`);
      // IP header: only AH rejects a modified source address by itself
      const headerDefended = cell(col, mode, 'spoof').outcome === 'defended';
      assert.equal(headerDefended, col === 'AH' || col === 'AH_ESP', `header ${col}/${mode}`);
      assert.equal(claim('header', col) === 'no' || claim('header', col) === 'partial', true);
      if (col === 'AH' || col === 'AH_ESP') assert.equal(claim('header', col), 'partial');
      if (col === 'ESP' || col === 'NONE') assert.equal(claim('header', col), 'no');
    }
  }
  assert.equal(claim('encryption', 'AH'), 'no');
  assert.equal(claim('encryption', 'ESP'), 'yes');
});

test('verification matrix: expected outcome for all 35 cases', async () => {
  const rows = await runMatrix();
  assert.equal(rows.length, 7);
  const outcomes = (r) => ['sniff', 'tamper', 'forge', 'replay', 'spoof'].map((a) => r.cells[a].outcome).join(' ');
  const get = (p, m) => outcomes(rows.find((r) => r.protection === p && r.mode === m));
  assert.equal(get('NONE', 'transport'), 'sniff succeeded succeeded succeeded succeeded');
  assert.equal(get('AH', 'transport'), 'sniff defended defended defended defended');
  assert.equal(get('AH', 'tunnel'), 'sniff defended defended defended defended');
  assert.equal(get('ESP', 'transport'), 'sniff defended defended defended succeeded');
  assert.equal(get('ESP', 'tunnel'), 'sniff defended defended defended no-effect');
  assert.equal(get('AH_ESP', 'transport'), 'sniff defended defended defended defended');
  assert.equal(get('AH_ESP', 'tunnel'), 'sniff defended defended defended defended');
  const strict = await runMatrix({ strictSelector: true });
  assert.equal(strict.find((r) => r.protection === 'ESP' && r.mode === 'transport').cells.spoof.outcome, 'defended');
});
