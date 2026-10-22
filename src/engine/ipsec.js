// IPsec packet processing: outbound protection (AH / ESP / both, transport / tunnel) and inbound
// verification. EDUCATIONAL SIMULATION - formats follow RFC 4302 (AH) and RFC 4303 (ESP) in structure,
// but this is not a production IPsec implementation and byte-level interoperability is not claimed.
//
//   ESP packet : IP | ESP header (SPI, Seq) | IV | AES-CBC( data | padding | pad length | next header ) | ICV
//   AH packet  : IP | AH header (next hdr, len, rsvd, SPI, Seq) | ICV | data
//   Both       : IP | AH | ESP ...   (ESP is applied first, then AH over the result)
//   Tunnel     : the whole original IP packet becomes the protected data behind a NEW outer IP header
//
// The receiver (processInbound) works ONLY from the bytes it receives plus its own SA database and
// policy. It never looks at what the UI has selected.

import {
  SimError, concat, u32, r32, hex32, constantTimeEqual, randomBytes,
} from './bytes.js';
import { computeIcv, aesCbcEncrypt, aesCbcDecrypt, ALG } from './crypto.js';
import {
  PROTO, IPV4_HEADER_LEN, buildIPv4Header, parseIPv4, rewriteIPv4, zeroMutableFields,
} from './ipv4.js';
import { PROTECTIONS, MODES, PROTECTION_LABEL, requiredProtocols } from './sa.js';

export const AH_LEN = 12 + ALG.ICV_LEN; // fixed fields + ICV = 28 bytes
export const AH_LEN_FIELD = AH_LEN / 4 - 2; // "Payload Len" = length in 32-bit words minus 2 (RFC 4302) = 5
export const ESP_HEADER_LEN = 8;

// ---------------------------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------------------------

export async function protect({ packet, protection, mode, sas = {}, tunnel = null, id = 0 }) {
  if (!PROTECTIONS.includes(protection)) throw new SimError('BAD_PROTECTION', `Unknown protection "${protection}"`);
  const need = requiredProtocols(protection);
  const steps = [];
  const applied = { ah: false, esp: false, tunnel: false };
  if (!need.ah && !need.esp) return { wire: packet.slice(), applied, seqs: {}, spis: {}, steps };

  if (!MODES.includes(mode)) throw new SimError('BAD_MODE', `Unknown mode "${mode}"`);
  const inner = parseIPv4(packet);
  if (!inner.valid) throw new SimError('BAD_PACKET', inner.error);
  if (need.ah && !sas.ah) throw new SimError('NO_SA', 'No outbound AH SA available');
  if (need.esp && !sas.esp) throw new SimError('NO_SA', 'No outbound ESP SA available');
  for (const sa of [need.ah && sas.ah, need.esp && sas.esp]) {
    if (sa && sa.mode !== mode) throw new SimError('SA_MODE', `${sa.protocol} SA is for ${sa.mode} mode, not ${mode}`);
  }
  const tunnelMode = mode === 'tunnel';
  if (tunnelMode && !tunnel) throw new SimError('NO_TUNNEL', 'Tunnel mode needs outer (gateway) addresses');

  steps.push({ level: 'info', text: `IPsec processing started: ${PROTECTION_LABEL[protection]}, ${mode} mode` });
  if (need.ah) steps.push({ level: 'info', text: `SA selected: AH, SPI ${hex32(sas.ah.spi)}` });
  if (need.esp) steps.push({ level: 'info', text: `SA selected: ESP, SPI ${hex32(sas.esp.spi)}` });

  // What the IPsec layer protects, and which protocol number is hidden behind it.
  let body;
  let nextHeader;
  if (tunnelMode) {
    body = packet;
    nextHeader = PROTO.IPIP;
    applied.tunnel = true;
    steps.push({ level: 'info', text: `Tunnel mode: original ${packet.length}-byte IP packet becomes the protected payload; new outer header ${tunnel.src} → ${tunnel.dst}` });
  } else {
    body = packet.subarray(IPV4_HEADER_LEN);
    nextHeader = inner.protocol;
  }
  const outer = tunnelMode
    ? { src: tunnel.src, dst: tunnel.dst, ttl: 64, tos: 0, id, dontFragment: true }
    : { src: inner.src, dst: inner.dst, ttl: inner.ttl, tos: inner.tos, id: inner.id, dontFragment: inner.flags.df };

  const seqs = {};
  const spis = {};
  let finalProtocol = nextHeader;

  // ---- ESP (applied first) ----
  if (need.esp) {
    const sa = sas.esp;
    const seq = sa.nextSeq();
    seqs.esp = seq;
    spis.esp = sa.spi;
    // Trailer: padding (1,2,3,...) + pad length + next header, so the encrypted block is a multiple of 16 bytes.
    const padLen = (ALG.BLOCK - ((body.length + 2) % ALG.BLOCK)) % ALG.BLOCK;
    const padding = Uint8Array.from({ length: padLen }, (_, i) => i + 1);
    const plaintext = concat(body, padding, Uint8Array.of(padLen, nextHeader));
    steps.push({ level: 'info', text: `ESP padding added: ${padLen} byte(s) so data + trailer fill whole 16-byte AES blocks` });
    const iv = randomBytes(ALG.IV_LEN);
    const ciphertext = await aesCbcEncrypt(sa.encKey, iv, plaintext);
    steps.push({ level: 'ok', text: `ESP encryption completed: ${ALG.ENC}, fresh random ${ALG.IV_LEN}-byte IV, ${ciphertext.length} bytes of ciphertext` });
    const header = concat(u32(sa.spi), u32(seq));
    const icv = await computeIcv(sa.authKey, concat(header, iv, ciphertext)); // encrypt-then-MAC
    steps.push({ level: 'ok', text: `ESP authentication generated: ICV = ${ALG.AUTH} over ESP header + IV + ciphertext (Seq ${seq})` });
    body = concat(header, iv, ciphertext, icv);
    nextHeader = PROTO.ESP;
    finalProtocol = PROTO.ESP;
    applied.esp = true;
  }

  // ---- AH (applied last, covers everything after it and the outer IP header's immutable fields) ----
  let wire;
  if (need.ah) {
    const sa = sas.ah;
    const seq = sa.nextSeq();
    seqs.ah = seq;
    spis.ah = sa.spi;
    const outerHeader = buildIPv4Header({
      ...outer, protocol: PROTO.AH, payloadLength: AH_LEN + body.length,
    });
    const ahHeader = (icv) => concat(Uint8Array.of(nextHeader, AH_LEN_FIELD, 0, 0), u32(sa.spi), u32(seq), icv);
    const icv = await computeIcv(
      sa.authKey,
      concat(zeroMutableFields(outerHeader), ahHeader(new Uint8Array(ALG.ICV_LEN)), body),
    );
    steps.push({ level: 'ok', text: `AH authentication generated: ICV = ${ALG.AUTH} over IP header (mutable fields zeroed) + AH header + payload (Seq ${seq})` });
    wire = concat(outerHeader, ahHeader(icv), body);
    applied.ah = true;
    finalProtocol = PROTO.AH;
  } else {
    wire = concat(buildIPv4Header({ ...outer, protocol: finalProtocol, payloadLength: body.length }), body);
  }
  steps.push({ level: 'info', text: `Protected packet constructed: ${packet.length} → ${wire.length} bytes (+${wire.length - packet.length}), IP protocol field = ${finalProtocol}` });
  return { wire, applied, seqs, spis, steps };
}

// ---------------------------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------------------------

/**
 * endpoint = { name, sad, policy: { protection, mode }, strictSelector }
 * The policy is the receiver's own configuration ("what must arrive protected"). Which protocols and
 * which mode a packet actually used is read from the packet, never assumed.
 */
export async function processInbound(wire, endpoint) {
  const steps = [];
  const add = (id, title, status, detail) => steps.push({ id, title, status, detail });
  const result = {
    accepted: false,
    droppedAt: null,
    reason: null,
    steps,
    applied: { ah: false, esp: false, tunnel: false },
    checks: {},
    spis: {},
    seqs: {},
    plaintext: null,
    payload: null,
    delivered: null,
    outerIp: null,
    verifier: endpoint.name,
  };
  const fail = (stage, reason) => {
    result.droppedAt = stage;
    result.reason = reason;
    add('deliver', 'Deliver packet', 'skip', `Not delivered: ${reason}`);
    return result;
  };

  // 1. Parse and validate the IPv4 header
  const ip = parseIPv4(wire);
  if (!ip.valid) {
    add('ip', 'Parse and validate IPv4 header', 'fail', ip.error);
    return fail('IPv4 validation', ip.error);
  }
  if (ip.totalLength !== wire.length) {
    const msg = `IPv4 total length field (${ip.totalLength}) does not match the received length (${wire.length})`;
    add('ip', 'Parse and validate IPv4 header', 'fail', msg);
    return fail('IPv4 validation', msg);
  }
  if (!ip.checksumValid) {
    const msg = 'IPv4 header checksum is invalid';
    add('ip', 'Parse and validate IPv4 header', 'fail', msg);
    return fail('IPv4 validation', msg);
  }
  result.outerIp = ip;
  add('ip', 'Parse and validate IPv4 header', 'pass', `IPv4, ${ip.src} → ${ip.dst}, TTL ${ip.ttl}, length ${ip.totalLength}, checksum 0x${ip.checksum.toString(16).padStart(4, '0')} valid`);

  let data = wire.subarray(IPV4_HEADER_LEN);
  let proto = ip.protocol;
  let firstSa = null;

  // 2..8. Walk the IPsec headers that are actually present (AH, then ESP)
  for (let guard = 0; guard < 4; guard++) {
    if (proto === PROTO.AH) {
      if (result.applied.ah) return fail('Protocol parsing', 'Nested AH headers are not supported');
      if (result.applied.esp) return fail('Protocol parsing', 'AH inside ESP is not supported by this simulator');
      if (data.length < AH_LEN) {
        add('identify', 'Identify protocol: AH', 'fail', 'Truncated AH header');
        return fail('Protocol parsing', 'Truncated AH header');
      }
      const nextHdr = data[0];
      if ((data[1] + 2) * 4 !== AH_LEN) {
        add('identify', 'Identify protocol: AH', 'fail', `Unsupported AH length field ${data[1]}`);
        return fail('Protocol parsing', `Unsupported AH length field ${data[1]}`);
      }
      const spi = r32(data, 4);
      const seq = r32(data, 8);
      const tag = data.subarray(12, AH_LEN);
      const rest = data.subarray(AH_LEN);
      result.spis.ah = spi;
      result.seqs.ah = seq;
      add('identify', 'Identify protocol: IP protocol field = 51 (AH)', 'pass', `AH header parsed: next header ${nextHdr}, SPI ${hex32(spi)}, Seq ${seq}`);
      const chk = (result.checks.ah = { spi, seq, sa: 'not-evaluated', replay: 'not-evaluated', icv: 'not-evaluated' });

      const sa = endpoint.sad.lookup(spi, 'AH');
      if (!sa) {
        chk.sa = 'fail';
        const msg = `No inbound AH Security Association for SPI ${hex32(spi)}`;
        add('sa', 'Locate Security Association (AH)', 'fail', msg);
        return fail('SA lookup', msg);
      }
      chk.sa = 'pass';
      firstSa ??= sa;
      add('sa', 'Locate Security Association (AH)', 'pass', `SPI ${hex32(spi)} → AH SA (${sa.authAlg}, ${sa.mode} mode)`);

      const rc = sa.replay.check(seq);
      chk.replayKind = rc.kind;
      chk.replayReason = rc.reason;
      if (!rc.ok) {
        chk.replay = 'fail';
        add('replay', 'Anti-replay check (AH)', 'fail', rc.reason);
        return fail('Anti-replay check', rc.reason);
      }
      chk.replay = 'pass';
      add('replay', 'Anti-replay check (AH)', 'pass', rc.reason);

      const expected = await computeIcv(
        sa.authKey,
        concat(zeroMutableFields(wire.subarray(0, IPV4_HEADER_LEN)), data.subarray(0, 12), new Uint8Array(ALG.ICV_LEN), rest),
      );
      if (!constantTimeEqual(expected, tag)) {
        chk.icv = 'fail';
        add('icv', 'Verify AH Integrity Check Value', 'fail', 'ICV mismatch: the packet was modified or was not produced with this SA\'s key');
        return fail('ICV verification', 'AH ICV mismatch - packet modified or forged');
      }
      chk.icv = 'pass';
      add('icv', 'Verify AH Integrity Check Value', 'pass', `ICV verified (${ALG.AUTH}, constant-time comparison): packet authentic and unmodified`);
      sa.replay.update(seq);
      add('replay-update', 'Update replay window (AH)', 'pass', `Window advanced after successful authentication (highest = ${sa.replay.highest})`);
      result.applied.ah = true;
      data = rest;
      proto = nextHdr;
      continue;
    }

    if (proto === PROTO.ESP) {
      if (result.applied.esp) return fail('Protocol parsing', 'Nested ESP headers are not supported');
      const minLen = ESP_HEADER_LEN + ALG.IV_LEN + ALG.BLOCK + ALG.ICV_LEN;
      if (data.length < minLen) {
        add('identify', 'Identify protocol: ESP', 'fail', 'Truncated ESP packet');
        return fail('Protocol parsing', 'Truncated ESP packet');
      }
      const spi = r32(data, 0);
      const seq = r32(data, 4);
      result.spis.esp = spi;
      result.seqs.esp = seq;
      add('identify', `Identify protocol: ${result.applied.ah ? 'AH next header = 50' : 'IP protocol field = 50'} (ESP)`, 'pass', `ESP header parsed: SPI ${hex32(spi)}, Seq ${seq}`);
      const chk = (result.checks.esp = { spi, seq, sa: 'not-evaluated', replay: 'not-evaluated', icv: 'not-evaluated', decrypt: 'not-evaluated' });

      const sa = endpoint.sad.lookup(spi, 'ESP');
      if (!sa) {
        chk.sa = 'fail';
        const msg = `No inbound ESP Security Association for SPI ${hex32(spi)}`;
        add('sa', 'Locate Security Association (ESP)', 'fail', msg);
        return fail('SA lookup', msg);
      }
      chk.sa = 'pass';
      firstSa ??= sa;
      add('sa', 'Locate Security Association (ESP)', 'pass', `SPI ${hex32(spi)} → ESP SA (${sa.encAlg} + ${sa.authAlg}, ${sa.mode} mode)`);

      const rc = sa.replay.check(seq);
      chk.replayKind = rc.kind;
      chk.replayReason = rc.reason;
      if (!rc.ok) {
        chk.replay = 'fail';
        add('replay', 'Anti-replay check (ESP)', 'fail', rc.reason);
        return fail('Anti-replay check', rc.reason);
      }
      chk.replay = 'pass';
      add('replay', 'Anti-replay check (ESP)', 'pass', rc.reason);

      const tag = data.subarray(data.length - ALG.ICV_LEN);
      const authenticated = data.subarray(0, data.length - ALG.ICV_LEN);
      const expected = await computeIcv(sa.authKey, authenticated);
      if (!constantTimeEqual(expected, tag)) {
        chk.icv = 'fail';
        add('icv', 'Verify ESP Integrity Check Value', 'fail', 'ICV mismatch: ciphertext/header was modified or was not produced with this SA\'s key (nothing is decrypted)');
        return fail('ICV verification', 'ESP ICV mismatch - packet modified or forged');
      }
      chk.icv = 'pass';
      add('icv', 'Verify ESP Integrity Check Value', 'pass', `ICV verified over ESP header + IV + ciphertext (${ALG.AUTH}); decryption is only attempted after this`);
      sa.replay.update(seq);
      add('replay-update', 'Update replay window (ESP)', 'pass', `Window advanced after successful authentication (highest = ${sa.replay.highest})`);

      const iv = data.subarray(ESP_HEADER_LEN, ESP_HEADER_LEN + ALG.IV_LEN);
      const ciphertext = data.subarray(ESP_HEADER_LEN + ALG.IV_LEN, data.length - ALG.ICV_LEN);
      if (ciphertext.length % ALG.BLOCK !== 0 || ciphertext.length === 0) {
        chk.decrypt = 'fail';
        add('decrypt', 'Decrypt ESP payload', 'fail', 'Ciphertext is not a whole number of AES blocks');
        return fail('Decryption', 'Ciphertext length is not a multiple of the AES block size');
      }
      const plaintext = await aesCbcDecrypt(sa.encKey, iv, ciphertext);
      const padLen = plaintext[plaintext.length - 2];
      const nextHdr = plaintext[plaintext.length - 1];
      let padOk = padLen <= plaintext.length - 2;
      for (let i = 0; padOk && i < padLen; i++) if (plaintext[plaintext.length - 3 - padLen + i + 1] !== i + 1) padOk = false;
      if (!padOk) {
        chk.decrypt = 'fail';
        add('decrypt', 'Decrypt ESP payload', 'fail', 'ESP padding check failed');
        return fail('Decryption', 'ESP padding check failed');
      }
      chk.decrypt = 'pass';
      result.plaintext = plaintext;
      result.applied.esp = true;
      add('decrypt', 'Decrypt ESP payload and strip trailer', 'pass', `${ALG.ENC} decrypted ${ciphertext.length} bytes; removed ${padLen} padding byte(s); next header = ${nextHdr}`);
      data = plaintext.subarray(0, plaintext.length - 2 - padLen);
      proto = nextHdr;
      continue;
    }
    break;
  }

  // 9. Remove encapsulation
  let delivered;
  const secured = result.applied.ah || result.applied.esp;
  if (secured && proto === PROTO.IPIP) {
    const inner = parseIPv4(data);
    if (!inner.valid || inner.totalLength !== data.length || !inner.checksumValid) {
      const msg = 'Inner IPv4 header is invalid after decapsulation';
      add('decap', 'Remove tunnel encapsulation', 'fail', msg);
      return fail('Decapsulation', msg);
    }
    result.applied.tunnel = true;
    delivered = data.slice();
    result.innerIp = inner;
    add('decap', 'Remove tunnel encapsulation (outer IP header discarded)', 'pass', `Inner packet recovered: ${inner.src} → ${inner.dst}, TTL ${inner.ttl}`);
    result.payload = data.slice(IPV4_HEADER_LEN);
  } else {
    delivered = concat(
      rewriteIPv4(wire.subarray(0, IPV4_HEADER_LEN), { protocol: proto, totalLength: IPV4_HEADER_LEN + data.length }),
      data,
    );
    result.payload = data.slice();
    if (secured) add('decap', 'Remove IPsec headers (transport mode)', 'pass', `IP protocol restored to ${proto}; IP header stays in place`);
  }

  // 10. Inbound policy: was this packet protected the way the policy demands?
  const need = requiredProtocols(endpoint.policy.protection);
  const problems = [];
  if (need.ah !== result.applied.ah) problems.push(need.ah ? 'AH required but absent' : 'unexpected AH');
  if (need.esp !== result.applied.esp) problems.push(need.esp ? 'ESP required but absent' : 'unexpected ESP');
  if (secured && endpoint.policy.mode !== (result.applied.tunnel ? 'tunnel' : 'transport')) {
    problems.push(`${endpoint.policy.mode} mode required but packet used ${result.applied.tunnel ? 'tunnel' : 'transport'} mode`);
  }
  if (problems.length) {
    const msg = `Policy violation: ${problems.join('; ')}`;
    add('policy', 'Check inbound security policy', 'fail', msg);
    return fail('Policy check', msg);
  }
  add('policy', 'Check inbound security policy', 'pass', secured
    ? `Packet used ${[result.applied.ah && 'AH', result.applied.esp && 'ESP'].filter(Boolean).join(' + ')} in ${result.applied.tunnel ? 'tunnel' : 'transport'} mode as the policy requires`
    : 'Policy for this flow: no IPsec (bypass). The packet is unprotected, so nothing can be authenticated');

  // Optional strict source-address selector check (RFC 4301 section 5.2 style); off by default.
  if (endpoint.strictSelector && firstSa) {
    const innerOk = !result.applied.tunnel || (result.innerIp.src === firstSa.trafficSrc && result.innerIp.dst === firstSa.trafficDst);
    if (ip.src !== firstSa.peerSrc || !innerOk) {
      const msg = `Source address ${ip.src} does not match the SA's peer ${firstSa.peerSrc}`;
      add('selector', 'Inbound selector check (strict mode)', 'fail', msg);
      return fail('Selector check', msg);
    }
    add('selector', 'Inbound selector check (strict mode)', 'pass', `Source ${ip.src} matches the SA's peer address`);
  } else if (secured) {
    add('selector', 'Inbound selector check', 'info', 'Disabled: the outer source address is not checked against the SA (enable "strict selector check" to see the difference)');
  }

  // 11. Accept
  result.accepted = true;
  result.delivered = delivered;
  add('deliver', 'Deliver packet', 'pass', `Packet accepted and payload recovered (${result.payload.length} bytes)`);
  return result;
}
