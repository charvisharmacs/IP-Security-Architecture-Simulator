// Simplified SA establishment - EDUCATIONAL MODEL, NOT A FULL IKEv2 IMPLEMENTATION.
//
// Real IPsec peers set up Security Associations with IKEv2 (RFC 7296). This module keeps the idea and
// uses real cryptography for the key steps, but leaves out the protocol machinery:
//   included : proposal / selection, ephemeral ECDH (P-256), pre-shared-key peer authentication over
//              the exchange transcript (HMAC), HKDF key derivation, SPI assignment, SA creation
//   omitted  : IKE_SA_INIT / IKE_AUTH message formats, cookies, multiple proposals, certificates / EAP,
//              NAT traversal, lifetimes and re-keying, CHILD_SA rekey, Traffic Selector negotiation
//
//   Initiator -> proposal (protocols, mode, algorithms)
//   Responder -> accepts, picks SPIs for its inbound SAs
//   both      -> exchange ECDH public values, derive the same shared secret
//   both      -> prove knowledge of the pre-shared key (HMAC over the transcript)
//   both      -> HKDF the secret into per-SA keys; each side derives its own copy
//   result    -> one SA per protocol in each side's database (AH and ESP are separate SAs)

import {
  SimError, concat, encoder, randomBytes, toHex, hex32, constantTimeEqual, r32,
} from './bytes.js';
import {
  ALG, generateEcdhKeyPair, ecdhSharedSecret, hkdfSha256, hmacSha256, sha256,
} from './crypto.js';
import { SecurityAssociation, requiredProtocols } from './sa.js';

function newSpi(taken) {
  for (;;) {
    const spi = r32(randomBytes(4), 0);
    if (spi >= 256 && !taken.has(spi)) {
      taken.add(spi);
      return spi;
    }
  }
}

/**
 * Establish SAs for one flow. Returns the transmit-side SAs (initiator's database), the receive-side
 * SAs (responder's database) and a list of step records describing what really happened.
 */
export async function establishSAs({
  protection, mode, hostSrc, hostDst, gwSrc, gwDst, psk, responderPsk = psk, takenSpis = new Set(),
}) {
  const need = requiredProtocols(protection);
  if (!need.ah && !need.esp) throw new SimError('NO_SA_NEEDED', 'No IPsec: no SA is required');
  const tunnel = mode === 'tunnel';
  const peerSrc = tunnel ? gwSrc : hostSrc;
  const peerDst = tunnel ? gwDst : hostDst;
  const protocols = [need.ah && 'AH', need.esp && 'ESP'].filter(Boolean);
  const steps = [];

  // 1. Proposal
  const proposal = {
    protocols,
    mode,
    auth: ALG.AUTH,
    enc: need.esp ? ALG.ENC : null,
    keyExchange: 'ECDH P-256',
    kdf: 'HKDF-SHA-256',
  };
  steps.push({
    id: 'propose', actor: 'Initiator', title: 'Initiator proposes security parameters',
    detail: `${protocols.join(' + ')} in ${mode} mode; integrity ${ALG.AUTH}${need.esp ? `; encryption ${ALG.ENC}` : ''}; ${proposal.keyExchange} key exchange`,
  });
  steps.push({
    id: 'accept', actor: 'Responder', title: 'Responder accepts the proposal',
    detail: 'The only proposal offered is supported, so it is selected (a real IKEv2 responder chooses among several).',
  });

  // 2. Key agreement
  const ini = await generateEcdhKeyPair();
  const rsp = await generateEcdhKeyPair();
  const secretI = await ecdhSharedSecret(ini.privateKey, rsp.publicRaw);
  const secretR = await ecdhSharedSecret(rsp.privateKey, ini.publicRaw);
  if (!constantTimeEqual(secretI, secretR)) throw new SimError('DH_MISMATCH', 'Key agreement failed');
  const fingerprint = toHex((await sha256(secretI)).slice(0, 6));
  steps.push({
    id: 'dh', actor: 'Both', title: 'Ephemeral ECDH key exchange',
    detail: `Public values exchanged (initiator ${toHex(ini.publicRaw.slice(1, 7))}…, responder ${toHex(rsp.publicRaw.slice(1, 7))}…). Both sides computed the same shared secret (SHA-256 fingerprint ${fingerprint}…). The secret itself never crosses the network.`,
  });

  // 3. Peer authentication with the pre-shared key over the transcript
  const transcript = concat(encoder.encode(JSON.stringify(proposal)), ini.publicRaw, rsp.publicRaw);
  // Each side MACs the transcript with its own copy of the key; the other side recomputes with ITS copy.
  const authI = await hmacSha256(psk, concat(encoder.encode('initiator'), transcript));
  const authR = await hmacSha256(responderPsk, concat(encoder.encode('responder'), transcript));
  const okI = constantTimeEqual(authI, await hmacSha256(responderPsk, concat(encoder.encode('initiator'), transcript)));
  const okR = constantTimeEqual(authR, await hmacSha256(psk, concat(encoder.encode('responder'), transcript)));
  if (!okI || !okR) throw new SimError('AUTH_FAILED', 'Peer authentication failed: the pre-shared keys differ');
  steps.push({
    id: 'auth', actor: 'Both', title: 'Peer authentication (pre-shared key)',
    detail: `Each side proves knowledge of the demo pre-shared key with HMAC over the exchange transcript (initiator ${toHex(authI.slice(0, 4))}…, responder ${toHex(authR.slice(0, 4))}…). Both verified. Demo key only: generated for this session.`,
  });

  // 4. Key derivation: each side derives independently; the SAs are built from each side's own copy.
  const salt = await sha256(transcript);
  const derive = async (secret, label, len) => hkdfSha256(secret, salt, encoder.encode(`ipsec-sim|${label}`), len);
  const keysI = {};
  const keysR = {};
  for (const [label, len] of [['AH-auth', 32], ['ESP-auth', 32], ['ESP-enc', 16]]) {
    keysI[label] = await derive(secretI, label, len);
    keysR[label] = await derive(secretR, label, len);
    if (!constantTimeEqual(keysI[label], keysR[label])) throw new SimError('KDF_MISMATCH', 'Key derivation mismatch');
  }
  steps.push({
    id: 'kdf', actor: 'Both', title: 'Key derivation (HKDF-SHA-256)',
    detail: `Separate keys per SA and per purpose: ${protocols.includes('AH') ? 'AH-auth, ' : ''}${need.esp ? 'ESP-auth, ESP-enc' : ''}. Using different keys for AH and ESP keeps the two SAs independent.`.replace(/, $/, ''),
  });

  // 5. SPI assignment + SA creation
  const tx = {};
  const rx = {};
  for (const protocol of protocols) {
    const spi = newSpi(takenSpis);
    const common = { protocol, spi, mode, peerSrc, peerDst, trafficSrc: hostSrc, trafficDst: hostDst };
    const key = (k) => (protocol === 'AH' ? { authKey: k['AH-auth'] } : { authKey: k['ESP-auth'], encKey: k['ESP-enc'] });
    tx[protocol.toLowerCase()] = new SecurityAssociation({ ...common, ...key(keysI) });
    rx[protocol.toLowerCase()] = new SecurityAssociation({ ...common, ...key(keysR) });
  }
  steps.push({
    id: 'spi', actor: 'Responder', title: 'SPI assignment',
    detail: protocols.map((p) => `${p}: SPI ${hex32(tx[p.toLowerCase()].spi)}`).join('   '),
  });
  steps.push({
    id: 'sa', actor: 'Both', title: 'Security Associations created',
    detail: `${protocols.length} one-way SA${protocols.length > 1 ? 's' : ''} installed in the sender's and the receiver's SA database (sequence counter = 0, replay window = ${rx[protocols[0].toLowerCase()].replay.size}).`,
  });
  steps.push({
    id: 'go', actor: 'Both', title: 'Secure communication can begin',
    detail: 'Packets now carry the SPI so the receiver can find the SA and its keys.',
  });
  return { tx, rx, steps, proposal };
}
