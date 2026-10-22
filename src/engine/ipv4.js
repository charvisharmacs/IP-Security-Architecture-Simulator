// IPv4 header construction, parsing, checksum, TTL handling and the AH mutable-field treatment.
// Educational scope: 20-byte headers only (no IP options, no fragmentation).

import {
  SimError, u16, r16, parseIPv4Address, formatIPv4Address, concat, toHex,
} from './bytes.js';

export const PROTO = Object.freeze({ IPIP: 4, ESP: 50, AH: 51, APP: 253 });

export const protoName = (p) =>
  ({ 4: 'IPv4-in-IPv4', 50: 'ESP', 51: 'AH', 253: 'Application payload' }[p] ?? `Protocol ${p}`);

export const IPV4_HEADER_LEN = 20;
export const MAX_PACKET = 65535;

/** Header checksum (RFC 791 / RFC 1071 one's-complement sum). The checksum field is treated as zero. */
export function ipv4Checksum(header) {
  let sum = 0;
  for (let i = 0; i < IPV4_HEADER_LEN; i += 2) {
    if (i === 10) continue;
    sum += (header[i] << 8) | header[i + 1];
  }
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

/** A header is valid when the one's-complement sum of all 16-bit words (checksum included) is 0xFFFF. */
export function verifyIPv4Checksum(header) {
  let sum = 0;
  for (let i = 0; i < IPV4_HEADER_LEN; i += 2) sum += (header[i] << 8) | header[i + 1];
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return sum === 0xffff;
}

function intIn(name, v, lo, hi) {
  if (!Number.isInteger(v) || v < lo || v > hi) throw new SimError('BAD_FIELD', `${name} must be an integer in ${lo}..${hi}`);
  return v;
}

export function buildIPv4Header({ src, dst, protocol, payloadLength, ttl = 64, tos = 0, id = 0, dontFragment = true }) {
  intIn('protocol', protocol, 0, 255);
  intIn('ttl', ttl, 0, 255);
  intIn('tos', tos, 0, 255);
  intIn('id', id, 0, 0xffff);
  intIn('payloadLength', payloadLength, 0, MAX_PACKET - IPV4_HEADER_LEN);
  const h = new Uint8Array(IPV4_HEADER_LEN);
  h[0] = 0x45; // version 4, IHL 5
  h[1] = tos;
  h.set(u16(IPV4_HEADER_LEN + payloadLength), 2);
  h.set(u16(id), 4);
  h.set(u16(dontFragment ? 0x4000 : 0), 6);
  h[8] = ttl;
  h[9] = protocol;
  h.set(parseIPv4Address(src), 12);
  h.set(parseIPv4Address(dst), 16);
  h.set(u16(ipv4Checksum(h)), 10);
  return h;
}

export function parseIPv4(bytes) {
  if (bytes.length < IPV4_HEADER_LEN) return { valid: false, error: 'Packet is shorter than a minimal IPv4 header' };
  const version = bytes[0] >> 4;
  const ihl = bytes[0] & 15;
  if (version !== 4) return { valid: false, error: `IP version ${version} is not IPv4` };
  if (ihl !== 5) return { valid: false, error: 'IPv4 options are not supported by this simulator (IHL must be 5)' };
  const flagsFrag = r16(bytes, 6);
  return {
    valid: true,
    version,
    ihl,
    headerLength: IPV4_HEADER_LEN,
    tos: bytes[1],
    totalLength: r16(bytes, 2),
    id: r16(bytes, 4),
    flags: { reserved: !!(flagsFrag & 0x8000), df: !!(flagsFrag & 0x4000), mf: !!(flagsFrag & 0x2000) },
    fragmentOffset: flagsFrag & 0x1fff,
    ttl: bytes[8],
    protocol: bytes[9],
    checksum: r16(bytes, 10),
    checksumValid: verifyIPv4Checksum(bytes),
    src: formatIPv4Address(bytes, 12),
    dst: formatIPv4Address(bytes, 16),
  };
}

/** Copy of `packet` with some header fields replaced and the checksum recomputed. */
export function rewriteIPv4(packet, { ttl, src, dst, protocol, totalLength, tos } = {}) {
  const out = packet.slice();
  if (ttl !== undefined) out[8] = intIn('ttl', ttl, 0, 255);
  if (protocol !== undefined) out[9] = intIn('protocol', protocol, 0, 255);
  if (tos !== undefined) out[1] = intIn('tos', tos, 0, 255);
  if (totalLength !== undefined) out.set(u16(intIn('totalLength', totalLength, 20, MAX_PACKET)), 2);
  if (src !== undefined) out.set(parseIPv4Address(src), 12);
  if (dst !== undefined) out.set(parseIPv4Address(dst), 16);
  out.set(u16(ipv4Checksum(out)), 10);
  return out;
}

/** What a router does: verify the checksum, check TTL, decrement TTL, fix the checksum. */
export function routerForward(packet) {
  const ip = parseIPv4(packet);
  if (!ip.valid) return { ok: false, reason: ip.error };
  if (!ip.checksumValid) return { ok: false, reason: 'IPv4 header checksum invalid (router discards the packet)' };
  if (ip.ttl <= 1) return { ok: false, reason: 'TTL expired in transit' };
  return { ok: true, packet: rewriteIPv4(packet, { ttl: ip.ttl - 1 }), ttl: ip.ttl - 1 };
}

/**
 * Educational treatment of IPv4 mutable fields for AH (RFC 4302 section 3.3.3.1.1.1):
 * TOS (DSCP/ECN), Flags, Fragment Offset, TTL and Header Checksum change in transit, so they are
 * set to zero before the ICV is computed or verified. Everything else is authenticated as-is.
 */
export const MUTABLE_FIELDS = Object.freeze(['TOS', 'Flags', 'Fragment offset', 'TTL', 'Header checksum']);

export function zeroMutableFields(header) {
  const h = header.slice(0, IPV4_HEADER_LEN);
  h[1] = 0; // TOS
  h[6] = 0; // flags + fragment offset
  h[7] = 0;
  h[8] = 0; // TTL
  h[10] = 0; // checksum
  h[11] = 0;
  return h;
}

/** Plain (unprotected) packet: IPv4 header + application payload (IP protocol 253, reserved for experimentation). */
export function makePlainPacket({ src, dst, payload, ttl = 64, id = 1 }) {
  const header = buildIPv4Header({ src, dst, protocol: PROTO.APP, payloadLength: payload.length, ttl, id });
  return concat(header, payload);
}

export const describeHeader = (h) => toHex(h.slice(0, IPV4_HEADER_LEN));
