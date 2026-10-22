// Byte helpers shared by the whole engine. No DOM access: runs in the browser and in Node.

export class SimError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SimError';
    this.code = code;
  }
}

export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8');

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += HEX[b];
  return s;
}

export function toHexSpaced(bytes) {
  return Array.from(bytes, (b) => HEX[b]).join(' ');
}

export function fromHex(str) {
  const clean = String(str).replace(/[\s:]/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new SimError('BAD_HEX', 'Invalid hexadecimal string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export const u16 = (n) => Uint8Array.of((n >>> 8) & 255, n & 255);
export const u32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
export const r16 = (b, o) => (b[o] << 8) | b[o + 1];
export const r32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
export const hex32 = (n) => '0x' + (n >>> 0).toString(16).padStart(8, '0');

export function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison (no early exit) used for every ICV check. */
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function equalBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function parseIPv4Address(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(text).trim());
  if (!m) throw new SimError('BAD_IP', `"${text}" is not a valid IPv4 address`);
  const octets = m.slice(1).map(Number);
  if (octets.some((o) => o > 255)) throw new SimError('BAD_IP', `"${text}" is not a valid IPv4 address`);
  return Uint8Array.from(octets);
}

export function formatIPv4Address(bytes, offset = 0) {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

export function isValidIPv4(text) {
  try {
    parseIPv4Address(text);
    return true;
  } catch {
    return false;
  }
}

/** Index of `needle` inside `hay`, or -1. Used to test whether plaintext is visible on the wire. */
export function indexOfBytes(hay, needle, from = 0) {
  if (!needle.length) return -1;
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
