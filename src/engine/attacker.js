// The attacker ("Mallory") sits on the untrusted network. Every action here changes real bytes; whether
// the attack works is decided later by the receiver's real verification code, never by this module.
//
//   sniff  : read the packet (always possible on the wire)
//   tamper : flip one bit inside the protected data
//   forge  : replace the packet with one built using attacker-chosen keys (SPI copied from the capture)
//   replay : re-send a previously captured packet (handled by the simulator, which keeps the capture)
//   spoof  : change the source address in the IP header and fix the header checksum so routers accept it

import {
  SimError, encoder, randomBytes, toHex, indexOfBytes, r32, formatIPv4Address,
} from './bytes.js';
import { PROTO, parseIPv4, rewriteIPv4, makePlainPacket, IPV4_HEADER_LEN } from './ipv4.js';
import { dissect } from './dissect.js';
import { protect } from './ipsec.js';
import { SecurityAssociation } from './sa.js';

export const ATTACKS = Object.freeze(['none', 'sniff', 'tamper', 'forge', 'replay', 'spoof']);
export const ATTACK_LABEL = Object.freeze({
  none: 'No attack',
  sniff: 'Sniff',
  tamper: 'Tamper',
  forge: 'Forge',
  replay: 'Replay',
  spoof: 'Modify source IP',
});

export const FORGED_TEXT = 'FORGED: transfer all funds to Mallory';

/** What an eavesdropper can learn from the captured bytes. */
export function analyzeExposure(wire, { payload, innerHeader = null }) {
  return {
    bytes: wire.length,
    payloadReadable: indexOfBytes(wire, payload) >= 0,
    // In tunnel mode: can the original source/destination addresses be read from the capture?
    innerAddressesReadable: innerHeader ? indexOfBytes(wire.subarray(IPV4_HEADER_LEN), innerHeader.subarray(12, 20)) >= 0 : null,
  };
}

export function tamper(wire) {
  const d = dissect(wire);
  const target =
    d.layers.find((l) => l.kind === 'ciphertext') ??
    [...d.layers].reverse().find((l) => l.kind === 'payload') ??
    d.layers[d.layers.length - 1];
  const offset = target.offset + target.length - 1;
  const out = wire.slice();
  const before = out[offset];
  out[offset] ^= 0x01;
  const hx = (b) => b.toString(16).padStart(2, '0');
  return {
    wire: out,
    action: 'tamper',
    changes: [{ field: `Byte ${offset} (inside "${target.name}")`, before: `0x${hx(before)}`, after: `0x${hx(out[offset])}`, offset }],
    logText: `Attacker flipped one bit at byte ${offset} (${target.name}): 0x${hx(before)} → 0x${hx(out[offset])}`,
  };
}

export function spoofSource(wire, newSrc) {
  const ip = parseIPv4(wire);
  if (!ip.valid) throw new SimError('BAD_PACKET', ip.error);
  const out = rewriteIPv4(wire, { src: newSrc });
  const after = parseIPv4(out);
  const hx = (n) => `0x${n.toString(16).padStart(4, '0')}`;
  return {
    wire: out,
    action: 'spoof',
    changes: [
      { field: 'IP source address', before: ip.src, after: after.src, offset: 12 },
      { field: 'IP header checksum (recomputed by attacker)', before: hx(ip.checksum), after: hx(after.checksum), offset: 10 },
    ],
    logText: `Attacker rewrote the IP source address ${ip.src} → ${after.src} and fixed the header checksum`,
  };
}

/** Build a replacement packet that looks like the captured one but uses keys the attacker invented. */
export async function forge(captured, { hostSrc, hostDst, id = 0 }) {
  const d = dissect(captured);
  const ip = parseIPv4(captured);
  if (!d.ok || !ip.valid) throw new SimError('BAD_PACKET', 'Cannot forge from an unparseable capture');
  const { ah, esp, tunnel } = d.summary;
  const payload = encoder.encode(FORGED_TEXT);

  if (!ah && !esp) {
    const wire = makePlainPacket({ src: ip.src, dst: ip.dst, payload, ttl: ip.ttl, id });
    return {
      wire, action: 'forge',
      changes: [{ field: 'Entire packet', before: 'sender\'s packet', after: 'attacker\'s packet' }],
      logText: 'Attacker dropped the original and injected its own packet (there is nothing to forge: no authentication exists)',
    };
  }
  const layerBytes = (id_) => d.layers.find((l) => l.id === id_)?.bytes;
  const fakeSa = (protocol, spi, seq) => {
    const sa = new SecurityAssociation({
      protocol, spi, mode: tunnel ? 'tunnel' : 'transport',
      authKey: randomBytes(32), encKey: protocol === 'ESP' ? randomBytes(16) : null,
      peerSrc: ip.src, peerDst: ip.dst, trafficSrc: hostSrc, trafficDst: hostDst,
    });
    sa.txSeq = seq - 1; // so the forged packet carries the same sequence number the genuine one had
    return sa;
  };
  const sas = {};
  let observed = '';
  if (ah) {
    const b = layerBytes('ah');
    sas.ah = fakeSa('AH', r32(b, 4), r32(b, 8));
    observed += `AH SPI 0x${sas.ah.spi.toString(16)} `;
  }
  if (esp) {
    const b = layerBytes('esp');
    sas.esp = fakeSa('ESP', r32(b, 0), r32(b, 4));
    observed += `ESP SPI 0x${sas.esp.spi.toString(16)}`;
  }
  const protection = ah && esp ? 'AH_ESP' : ah ? 'AH' : 'ESP';
  const mode = tunnel ? 'tunnel' : 'transport';
  const inner = makePlainPacket({ src: hostSrc, dst: hostDst, payload, ttl: tunnel ? 63 : ip.ttl, id });
  const res = await protect({
    packet: inner, protection, mode, sas, tunnel: tunnel ? { src: ip.src, dst: ip.dst } : null, id,
  });
  return {
    wire: res.wire,
    action: 'forge',
    changes: [
      { field: 'Payload', before: 'sender\'s message', after: FORGED_TEXT },
      { field: 'Keys used', before: 'real SA keys', after: `attacker-chosen random keys (copied: ${observed.trim()})` },
    ],
    logText: `Attacker replaced the packet with a forged ${protection.replace('_', ' + ')} packet using invented keys (${observed.trim()})`,
  };
}

export const describeIp = (wire) => {
  const ip = parseIPv4(wire);
  return ip.valid ? `${ip.src} → ${ip.dst}` : 'unparseable';
};

export { formatIPv4Address, toHex, PROTO };
