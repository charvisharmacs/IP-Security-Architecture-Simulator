// Security status shown in the UI. Every value is derived from what the receiver's verification code
// actually did (receive.checks) and from what the attacker could read on the wire (exposure).
//
// States: 'verified' | 'failed' | 'not-provided' | 'unknown' (not evaluated because the packet was
// dropped earlier in the pipeline).

import { requiredProtocols } from './sa.js';

export const STATE_LABEL = Object.freeze({
  verified: '✓ VERIFIED',
  failed: '✗ FAILED',
  'not-provided': 'NOT PROVIDED',
  unknown: '—',
});

function fromChecks(provided, receive, field) {
  const names = ['ah', 'esp'].filter((p) => provided[p]);
  if (!names.length) return 'not-provided';
  const results = names.map((p) => receive?.checks?.[p]?.[field] ?? 'not-evaluated');
  if (results.includes('fail')) return 'failed';
  if (results.every((r) => r === 'pass')) return 'verified';
  return 'unknown';
}

export function headerCoverage(protection, mode) {
  const p = requiredProtocols(protection);
  if (!p.ah && !p.esp) return { state: 'not-provided', text: 'IP header is not protected' };
  if (p.ah) {
    return {
      state: 'verified',
      text: 'AH authenticates the immutable IP header fields (TOS, flags, fragment offset, TTL and checksum are excluded)',
    };
  }
  return mode === 'tunnel'
    ? { state: 'not-provided', text: 'Outer IP header is NOT covered by ESP; the original header is encrypted and authenticated inside' }
    : { state: 'not-provided', text: 'ESP does NOT cover the IP header (only the ESP header, IV and ciphertext)' };
}

export function computeStatus({ protection, mode, exposure, receive, accepted }) {
  const provided = requiredProtocols(protection);
  const any = provided.ah || provided.esp;

  let confidentiality;
  if (!provided.esp) {
    confidentiality = { state: 'not-provided', detail: provided.ah ? 'AH never encrypts: the payload is readable on the wire' : 'No encryption: the payload is readable on the wire' };
  } else if (exposure?.payloadReadable) {
    confidentiality = { state: 'failed', detail: 'The payload could be read from the captured bytes' };
  } else {
    confidentiality = { state: 'verified', detail: 'The payload does not appear anywhere in the captured bytes (only ciphertext)' };
  }

  const icvState = fromChecks(provided, receive, 'icv');
  const authDetail = {
    'not-provided': 'No ICV: the receiver cannot tell who sent the packet',
    verified: 'ICV matched: the sender holds the SA key',
    failed: 'ICV did not match: not produced with the SA key or modified',
    unknown: 'ICV was not evaluated: the packet was rejected earlier',
  }[icvState];
  const authentication = { state: icvState, detail: authDetail };
  const integrity = {
    state: icvState,
    detail: {
      'not-provided': 'No integrity protection: changes go unnoticed',
      verified: 'Same ICV check: the protected bytes are unmodified',
      failed: 'Same ICV check: the protected bytes were modified',
      unknown: 'ICV was not evaluated: the packet was rejected earlier',
    }[icvState],
  };

  const replayState = fromChecks(provided, receive, 'replay');
  const replayChecks = ['ah', 'esp'].map((p) => receive?.checks?.[p]).filter(Boolean);
  const antiReplay = {
    state: replayState,
    detail: !any
      ? 'No sequence numbers: duplicates are accepted'
      : replayState === 'verified'
        ? `Sequence ${replayChecks.map((c) => c.seq).join(' / ')} is new (inside the replay window)`
        : replayState === 'failed'
          ? (replayChecks.find((c) => c.replay === 'fail')?.replayReason ?? 'Replay detected')
          : 'Replay check was not reached',
  };

  return {
    confidentiality,
    authentication,
    integrity,
    antiReplay,
    headerCoverage: headerCoverage(protection, mode),
    packet: accepted
      ? { state: 'verified', label: 'ACCEPTED' }
      : { state: 'failed', label: 'REJECTED' },
  };
}
