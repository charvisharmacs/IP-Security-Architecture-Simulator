// Cryptographic mechanisms, all via the standard Web Crypto API (available in browsers and Node 20+).
//
//   ICV          : HMAC-SHA-256 truncated to 128 bits   (RFC 2104 + RFC 4868, AUTH_HMAC_SHA2_256_128)
//   ESP cipher   : AES-128 in CBC mode, random 16-byte IV (FIPS 197 + NIST SP 800-38A, RFC 3602)
//   SA keys      : ECDH P-256 shared secret -> HKDF-SHA-256 (educational SA establishment only)
//
// These are mechanisms used BY the IPsec protocols (AH / ESP); they are not protocols themselves.

import { SimError, concat } from './bytes.js';

const subtle = globalThis.crypto.subtle;

export const ALG = Object.freeze({
  AUTH: 'HMAC-SHA-256-128',
  ENC: 'AES-128-CBC',
  ICV_LEN: 16,
  IV_LEN: 16,
  BLOCK: 16,
  AUTH_KEY_LEN: 32,
  ENC_KEY_LEN: 16,
});

export async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

export async function hmacSha256(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

/** Integrity Check Value: first 128 bits of HMAC-SHA-256 (RFC 4868 section 2.3). */
export async function computeIcv(authKey, data) {
  return (await hmacSha256(authKey, data)).slice(0, ALG.ICV_LEN);
}

function checkAesArgs(key, iv, data, what) {
  if (key.length !== ALG.ENC_KEY_LEN) throw new SimError('BAD_KEY', 'AES-128 needs a 16-byte key');
  if (iv.length !== ALG.IV_LEN) throw new SimError('BAD_IV', 'AES-CBC needs a 16-byte IV');
  if (data.length === 0 || data.length % ALG.BLOCK !== 0) {
    throw new SimError('BAD_LENGTH', `${what} must be a non-zero multiple of 16 bytes`);
  }
}

/**
 * AES-128-CBC with NO padding added here (ESP supplies its own padding, RFC 4303 section 2.4).
 * Web Crypto always applies PKCS#7, so the extra final block it appends is dropped.
 */
export async function aesCbcEncrypt(key, iv, plaintext) {
  checkAesArgs(key, iv, plaintext, 'Plaintext');
  const k = await subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const out = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, k, plaintext));
  return out.slice(0, plaintext.length);
}

/** Inverse of aesCbcEncrypt. Re-creates the PKCS#7 block Web Crypto expects, then discards it. */
export async function aesCbcDecrypt(key, iv, ciphertext) {
  checkAesArgs(key, iv, ciphertext, 'Ciphertext');
  const kEnc = await subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const kDec = await subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt']);
  const lastBlock = ciphertext.slice(ciphertext.length - ALG.BLOCK);
  const padBlock = new Uint8Array(
    await subtle.encrypt({ name: 'AES-CBC', iv: lastBlock }, kEnc, new Uint8Array(0)),
  );
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, kDec, concat(ciphertext, padBlock)));
}

// ---- Key establishment primitives (used by the simplified SA establishment model) ----

export async function generateEcdhKeyPair() {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return { privateKey: pair.privateKey, publicRaw };
}

export async function ecdhSharedSecret(privateKey, peerPublicRaw) {
  const pub = await subtle.importKey('raw', peerPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256));
}

/** HKDF-SHA-256 (RFC 5869). */
export async function hkdfSha256(ikm, salt, info, length) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, length * 8));
}
