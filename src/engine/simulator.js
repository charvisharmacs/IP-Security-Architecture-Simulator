// Simulation orchestrator: builds a packet, applies IPsec, sends it across the simulated network
// (with an attacker and TTL-decrementing routers), verifies it at the receiving endpoint and reports
// everything the UI shows. All security outcomes come from protect() / processInbound().
//
// Topology
//   transport / no IPsec :  Host A ──► Untrusted Internet ──► Host B           (verification at Host B)
//   tunnel               :  Host A ──► Gateway A ──► Untrusted Internet ──► Gateway B ──► Host B
//                           (Gateway A encapsulates, Gateway B verifies and decapsulates)

import {
  SimError, encoder, decoder, randomBytes, parseIPv4Address, equalBytes, hex32, toHex,
} from './bytes.js';
import { PROTO, parseIPv4, makePlainPacket, routerForward, IPV4_HEADER_LEN } from './ipv4.js';
import {
  PROTECTIONS, MODES, PROTECTION_LABEL, requiredProtocols,
  SecurityAssociationDatabase,
} from './sa.js';
import { protect, processInbound } from './ipsec.js';
import { dissect } from './dissect.js';
import { establishSAs } from './establish.js';
import {
  ATTACKS, ATTACK_LABEL, analyzeExposure, tamper, spoofSource, forge,
} from './attacker.js';
import { computeStatus } from './status.js';

export const GATEWAY_A_IP = '203.0.113.1'; // TEST-NET-3 (RFC 5737)
export const GATEWAY_B_IP = '198.51.100.1'; // TEST-NET-2 (RFC 5737)
export const INTERNET_HOPS = 3;
export const MAX_PAYLOAD = 200;
export const NODE_LABEL = Object.freeze({
  hostA: 'Host A', gwA: 'Gateway A', internet: 'Untrusted Internet', gwB: 'Gateway B', hostB: 'Host B',
});

export const DEFAULT_CONFIG = Object.freeze({
  protection: 'ESP',
  mode: 'transport',
  srcIp: '192.168.1.10',
  dstIp: '192.168.2.20',
  payload: 'Hello Host B, the password is 1234',
  attack: 'none',
  spoofIp: '10.10.10.10',
  strictSelector: false,
});

export function normalizeConfig(raw = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...raw };
  if (!PROTECTIONS.includes(cfg.protection)) throw new SimError('BAD_PROTECTION', `Unknown protection "${cfg.protection}"`);
  if (!MODES.includes(cfg.mode)) throw new SimError('BAD_MODE', `Unknown mode "${cfg.mode}"`);
  if (!ATTACKS.includes(cfg.attack)) throw new SimError('BAD_ATTACK', `Unknown attack "${cfg.attack}"`);
  parseIPv4Address(cfg.srcIp);
  parseIPv4Address(cfg.dstIp);
  if (cfg.srcIp === cfg.dstIp) throw new SimError('BAD_IP', 'Source and destination addresses must differ');
  if (cfg.attack === 'spoof') parseIPv4Address(cfg.spoofIp);
  if (typeof cfg.payload !== 'string' || cfg.payload.length === 0) throw new SimError('BAD_PAYLOAD', 'Application payload must not be empty');
  if (encoder.encode(cfg.payload).length > MAX_PAYLOAD) throw new SimError('BAD_PAYLOAD', `Application payload is limited to ${MAX_PAYLOAD} bytes`);
  cfg.strictSelector = !!cfg.strictSelector;
  return cfg;
}

const ttlOf = (p) => parseIPv4(p).ttl;
const protoLabel = (p) => {
  const ip = parseIPv4(p);
  return ip.protocol === PROTO.AH ? 'AH' : ip.protocol === PROTO.ESP ? 'ESP' : 'IP';
};

export class Simulator {
  constructor() {
    this.reset();
  }

  /** Full reset: new pre-shared key, empty SA databases, packet counter back to zero. */
  reset() {
    this.counter = 0;
    this.ipId = 0x1000;
    this.txSad = new SecurityAssociationDatabase();
    this.rxSad = new SecurityAssociationDatabase();
    this.takenSpis = new Set();
    this.psk = randomBytes(32);
    this.establishments = [];
  }

  /** Drop all SAs (keep the packet counter): the next protected packet triggers a new establishment. */
  rekey() {
    this.txSad.clear();
    this.rxSad.clear();
    this.takenSpis.clear();
    this.psk = randomBytes(32);
  }

  nextId() {
    this.ipId = (this.ipId + 1) & 0xffff;
    return this.ipId;
  }

  txSas(cfg) {
    const find = (protocol) => this.txSad.find({ protocol, mode: cfg.mode, trafficSrc: cfg.srcIp, trafficDst: cfg.dstIp });
    return { ah: find('AH'), esp: find('ESP') };
  }

  /** Establish whichever SAs this configuration needs and does not yet have. */
  async ensureSAs(cfg, L) {
    const need = requiredProtocols(cfg.protection);
    const have = this.txSas(cfg);
    const missing = { ah: need.ah && !have.ah, esp: need.esp && !have.esp };
    if (!missing.ah && !missing.esp) return null;
    const protection = missing.ah && missing.esp ? 'AH_ESP' : missing.ah ? 'AH' : 'ESP';
    L('info', `No SA for ${PROTECTION_LABEL[protection]} / ${cfg.mode} mode yet: running simplified SA establishment (educational model, not IKEv2)`, 'hostA');
    const est = await establishSAs({
      protection,
      mode: cfg.mode,
      hostSrc: cfg.srcIp,
      hostDst: cfg.dstIp,
      gwSrc: GATEWAY_A_IP,
      gwDst: GATEWAY_B_IP,
      psk: this.psk,
      responderPsk: this.psk.slice(),
      takenSpis: this.takenSpis,
    });
    for (const sa of Object.values(est.tx)) this.txSad.add(sa);
    for (const sa of Object.values(est.rx)) this.rxSad.add(sa);
    for (const s of est.steps) L('info', `SA establishment: ${s.title}`, 'hostA');
    const record = { at: this.counter, protection, mode: cfg.mode, steps: est.steps, proposal: est.proposal };
    this.establishments.push(record);
    return record;
  }

  /** One row per SA with both ends' state (sender counter, receiver replay window). */
  describeSAs() {
    return this.txSad.all().map((tx) => {
      const rx = this.rxSad.lookup(tx.spi, tx.protocol);
      return {
        protocol: tx.protocol,
        spi: tx.spi,
        mode: tx.mode,
        authAlg: tx.authAlg,
        encAlg: tx.encAlg,
        authKey: toHex(tx.authKey),
        encKey: tx.encKey ? toHex(tx.encKey) : null,
        txSeq: tx.txSeq,
        rxHighest: rx ? rx.replay.highest : 0,
        window: rx ? rx.replay.snapshot() : null,
        state: tx.state,
        trafficSrc: tx.trafficSrc,
        trafficDst: tx.trafficDst,
        peerSrc: tx.peerSrc,
        peerDst: tx.peerDst,
      };
    });
  }

  async run(rawCfg) {
    const cfg = normalizeConfig(rawCfg);
    const packetNo = ++this.counter;
    const log = [];
    const L = (level, text, node = null) => log.push({ n: log.length + 1, level, text, node });
    const secured = cfg.protection !== 'NONE';
    const tunnel = secured && cfg.mode === 'tunnel';
    const route = tunnel ? ['hostA', 'gwA', 'internet', 'gwB', 'hostB'] : ['hostA', 'internet', 'hostB'];
    const verifier = tunnel ? 'gwB' : 'hostB';
    const payloadBytes = encoder.encode(cfg.payload);

    const establishment = secured ? await this.ensureSAs(cfg, L) : null;

    // --- sender side -------------------------------------------------------------------------
    const original = makePlainPacket({ src: cfg.srcIp, dst: cfg.dstIp, payload: payloadBytes, ttl: 64, id: this.nextId() });
    L('info', `Packet created: ${cfg.srcIp} → ${cfg.dstIp}, ${payloadBytes.length}-byte application payload, TTL 64`, 'hostA');
    const frames = [{ node: 'hostA', text: 'Host A creates the IP packet', state: 'neutral', ttl: 64, proto: 'IP' }];
    let toProtect = original;
    let senderNode = 'hostA';
    if (tunnel) {
      const r = routerForward(original);
      toProtect = r.packet;
      senderNode = 'gwA';
      L('info', `Gateway A routes the packet toward the tunnel (inner TTL 64 → ${r.ttl})`, 'gwA');
      frames.push({ node: 'gwA', text: `Gateway A receives it and routes it into the tunnel (inner TTL ${r.ttl})`, state: 'neutral', ttl: r.ttl, proto: 'IP' });
    }
    let wire0 = toProtect;
    let protectInfo = { applied: { ah: false, esp: false, tunnel: false }, seqs: {}, spis: {}, steps: [] };
    if (secured) {
      protectInfo = await protect({
        packet: toProtect,
        protection: cfg.protection,
        mode: cfg.mode,
        sas: this.txSas(cfg),
        tunnel: { src: GATEWAY_A_IP, dst: GATEWAY_B_IP },
        id: this.nextId(),
      });
      for (const s of protectInfo.steps) L(s.level, s.text, senderNode);
      wire0 = protectInfo.wire;
      frames.push({
        node: senderNode, text: `${NODE_LABEL[senderNode]} applies ${PROTECTION_LABEL[cfg.protection]} (${cfg.mode})`,
        state: 'neutral', ttl: ttlOf(wire0), proto: protoLabel(wire0),
      });
    } else {
      L('warn', 'No IPsec: the packet is sent exactly as created (no authentication, integrity or confidentiality)', 'hostA');
    }
    L('info', `Packet transmitted: ${NODE_LABEL[senderNode]} → ${NODE_LABEL.internet} (${wire0.length} bytes, outer TTL ${ttlOf(wire0)})`, senderNode);

    const ctx = {
      cfg, L, tunnel, verifier, route, payloadBytes, original,
      endpoint: {
        name: NODE_LABEL[verifier],
        sad: this.rxSad,
        policy: { protection: cfg.protection, mode: cfg.mode },
        strictSelector: cfg.strictSelector,
      },
    };

    // --- network + receiver ------------------------------------------------------------------
    const transmissions = [];
    const mutate = {
      tamper: async (w) => tamper(w),
      spoof: async (w) => spoofSource(w, cfg.spoofIp),
      forge: async (w) => forge(w, { hostSrc: cfg.srcIp, hostDst: cfg.dstIp, id: this.nextId() }),
    }[cfg.attack] ?? null;

    const first = await this._transmit(ctx, {
      label: 'Sender → receiver', wire: wire0, frames, mutate, attack: cfg.attack, injected: false,
    });
    transmissions.push(first);
    if (cfg.attack === 'replay') {
      L('attack', 'Attacker re-injects the packet it captured earlier', 'internet');
      const second = await this._transmit(ctx, {
        label: 'Attacker replays the captured packet',
        wire: first.atAttacker.captured,
        frames: [{ node: 'internet', text: 'Attacker re-sends the captured packet', state: 'bad', ttl: ttlOf(first.atAttacker.captured), proto: protoLabel(first.atAttacker.captured) }],
        mutate: null, attack: 'replay', injected: true, skipCapture: true,
      });
      transmissions.push(second);
    }

    const primary = transmissions[transmissions.length - 1];
    return {
      packetNo,
      cfg,
      secured,
      tunnel,
      route,
      verifier,
      original: { bytes: original, view: dissect(original) },
      afterIpsec: { bytes: wire0, view: dissect(wire0) },
      applied: protectInfo.applied,
      seqs: protectInfo.seqs,
      spis: protectInfo.spis,
      establishment,
      transmissions,
      primary,
      log,
      overhead: wire0.length - original.length,
      sas: this.describeSAs(),
    };
  }

  async _transmit(ctx, { label, wire, frames, mutate, attack, injected, skipCapture = false }) {
    const { cfg, L, tunnel, verifier, original, payloadBytes, endpoint } = ctx;
    frames = [...frames];
    let cur = wire.slice();
    const fr = (node, text, state = 'neutral') => frames.push({ node, text, state, ttl: ttlOf(cur), proto: protoLabel(cur) });
    const hx = (w) => `${w.length} bytes`;

    // Enter the untrusted network
    fr('internet', 'Packet enters the untrusted network');
    const captured = cur.slice();
    const exposure = analyzeExposure(captured, { payload: payloadBytes, innerHeader: tunnel ? original : null });
    if (!skipCapture) {
      L('attack', `Attacker (Mallory) captured the packet (${hx(captured)}): payload ${exposure.payloadReadable ? 'READABLE' : 'not readable'}${exposure.innerAddressesReadable === null ? '' : `, original addresses ${exposure.innerAddressesReadable ? 'READABLE' : 'hidden'}`}`, 'internet');
    }
    const atAttacker = { captured, modified: null, changes: [], action: attack === 'none' ? 'none' : attack, exposure, note: '' };
    let injectedWire = null;
    if (mutate) {
      const m = await mutate(cur);
      cur = m.wire.slice();
      injectedWire = cur.slice();
      atAttacker.modified = injectedWire;
      atAttacker.changes = m.changes;
      L('attack', m.logText, 'internet');
      fr('internet', m.logText, 'bad');
    } else if (attack === 'sniff') {
      L('attack', 'Attacker only listens: the packet is forwarded unchanged', 'internet');
    }

    // Routers
    let dropped = null;
    const ttlIn = ttlOf(cur);
    for (let h = 1; h <= INTERNET_HOPS; h++) {
      const r = routerForward(cur);
      if (!r.ok) {
        dropped = { node: 'internet', stage: 'Router forwarding', reason: r.reason };
        L('error', `Router ${h} discarded the packet: ${r.reason}`, 'internet');
        fr('internet', `Router ${h} discarded the packet: ${r.reason}`, 'bad');
        break;
      }
      cur = r.packet;
    }
    if (!dropped) {
      L('info', `Packet forwarded by ${INTERNET_HOPS} routers: TTL ${ttlIn} → ${ttlOf(cur)}`, 'internet');
      fr('internet', `Forwarded by ${INTERNET_HOPS} routers (TTL ${ttlIn} → ${ttlOf(cur)})`);
    }

    // Receiver
    const arrived = cur.slice();
    let receive = null;
    let delivered = null;
    if (!dropped) {
      fr(verifier, `${NODE_LABEL[verifier]} receives the packet`);
      L('info', `Packet received at ${NODE_LABEL[verifier]}`, verifier);
      receive = await processInbound(cur, endpoint);
      for (const s of receive.steps) {
        L(s.status === 'fail' ? 'error' : s.status === 'pass' ? 'ok' : 'info', `${s.title}: ${s.detail}`, verifier);
      }
      if (!receive.accepted) {
        dropped = { node: verifier, stage: receive.droppedAt, reason: receive.reason };
        L('error', `PACKET REJECTED at ${NODE_LABEL[verifier]}: ${receive.reason}`, verifier);
        fr(verifier, `PACKET REJECTED: ${receive.reason}`, 'bad');
      } else {
        L('ok', `PACKET ACCEPTED at ${NODE_LABEL[verifier]}`, verifier);
        fr(verifier, `Packet accepted at ${NODE_LABEL[verifier]}`, 'ok');
        delivered = receive.delivered;
        if (tunnel) {
          const r = routerForward(delivered);
          if (!r.ok) {
            dropped = { node: 'gwB', stage: 'Router forwarding', reason: r.reason };
            delivered = null;
            L('error', `Gateway B could not forward the inner packet: ${r.reason}`, 'gwB');
          } else {
            delivered = r.packet;
            L('info', `Gateway B forwards the inner packet to Host B (inner TTL ${ttlOf(receive.delivered)} → ${r.ttl})`, 'gwB');
            fr('hostB', `Host B receives the inner packet (TTL ${r.ttl})`, 'ok');
          }
        }
      }
    }

    let delivery = null;
    if (delivered) {
      const d = parseIPv4(delivered);
      const o = parseIPv4(original);
      const dpayload = delivered.slice(IPV4_HEADER_LEN);
      delivery = {
        packet: delivered,
        src: d.src,
        dst: d.dst,
        ttl: d.ttl,
        payload: dpayload,
        text: decoder.decode(dpayload),
        matchesOriginal: d.src === o.src && d.dst === o.dst && equalBytes(dpayload, original.slice(IPV4_HEADER_LEN)),
      };
      L(delivery.matchesOriginal ? 'ok' : 'warn',
        `Host B delivers to the application: source ${delivery.src}, "${delivery.text}"${delivery.matchesOriginal ? '' : '  (differs from what Host A sent)'}`, 'hostB');
    }

    const accepted = !!delivered;
    const status = computeStatus({ protection: cfg.protection, mode: cfg.mode, exposure, receive, accepted });
    const droppedNode = dropped?.node ?? null;
    return {
      label,
      attack,
      injected,
      sent: wire.slice(),
      atAttacker,
      arrived,
      receive,
      accepted,
      dropped: dropped ? { ...dropped, label: NODE_LABEL[dropped.node] } : null,
      droppedNode,
      delivery,
      status,
      outcome: classify(attack, accepted, delivery),
      frames,
      views: {
        before: dissect(original),
        after: dissect(wire),
        attacker: dissect(captured),
        attackerModified: injectedWire ? dissect(injectedWire) : null,
        receiver: dissect(arrived, { plaintext: receive?.plaintext ?? null }),
      },
    };
  }
}

/** How did the attack end? 'defended' | 'succeeded' | 'no-effect' | 'leaked' | 'protected' | 'normal' */
export function classify(attack, accepted, delivery) {
  switch (attack) {
    case 'none':
      return 'normal';
    case 'sniff':
      return 'sniff';
    case 'tamper':
    case 'spoof':
      return !accepted ? 'defended' : delivery?.matchesOriginal ? 'no-effect' : 'succeeded';
    case 'forge':
    case 'replay':
      return accepted ? 'succeeded' : 'defended';
    default:
      return 'normal';
  }
}

export { ATTACK_LABEL, PROTECTION_LABEL, hex32 };
