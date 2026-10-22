// Packet dissector: turns raw bytes into labelled layers for the Packet Inspector.
// It needs no keys. When the receiver has decrypted an ESP payload it can pass the plaintext so
// the layers hidden inside the ciphertext are shown too.

import { r32, hex32, toHex, toHexSpaced, decoder } from './bytes.js';
import { PROTO, protoName, parseIPv4, IPV4_HEADER_LEN } from './ipv4.js';
import { AH_LEN, ESP_HEADER_LEN } from './ipsec.js';
import { ALG } from './crypto.js';

const f = (label, value, note = '', cov = '') => ({ label, value: String(value), note, cov });
const printable = (bytes) => decoder.decode(bytes).replace(/[^\x20-\x7e]/g, '·');

function ipFields(ip, ahSeen) {
  const cov = (mutable) => (!ahSeen ? 'none' : mutable ? 'zeroed' : 'auth');
  return [
    f('Version / IHL', `${ip.version} / ${ip.ihl} (${ip.headerLength} bytes)`, '', cov(false)),
    f('TOS', `0x${ip.tos.toString(16).padStart(2, '0')}`, 'mutable', cov(true)),
    f('Total length', ip.totalLength, 'bytes', cov(false)),
    f('Identification', `0x${ip.id.toString(16).padStart(4, '0')}`, '', cov(false)),
    f('Flags', ip.flags.df ? 'DF (don\'t fragment)' : ip.flags.mf ? 'MF' : 'none', 'mutable', cov(true)),
    f('Fragment offset', ip.fragmentOffset, 'mutable', cov(true)),
    f('TTL', ip.ttl, 'mutable: changes at every router', cov(true)),
    f('Protocol', `${ip.protocol} (${protoName(ip.protocol)})`, '', cov(false)),
    f('Header checksum', `0x${ip.checksum.toString(16).padStart(4, '0')} ${ip.checksumValid ? '✓ valid' : '✗ INVALID'}`, 'mutable', cov(true)),
    f('Source address', ip.src, '', cov(false)),
    f('Destination address', ip.dst, '', cov(false)),
  ];
}

export function dissect(wire, { plaintext = null } = {}) {
  const layers = [];
  const add = (l) => {
    const layer = { fields: [], auth: 'none', enc: false, desc: '', inside: false, ...l };
    layer.bytes = layer.bytes ?? wire.slice(layer.offset, layer.offset + layer.length);
    layers.push(layer);
    return layer;
  };
  const rest = (off, end, name = 'Remaining data') => {
    if (end > off) add({ id: `raw${off}`, kind: 'raw', name, offset: off, length: end - off });
  };

  const ip = parseIPv4(wire);
  if (!ip.valid) {
    add({ id: 'raw', kind: 'raw', name: 'Unparseable data', offset: 0, length: wire.length, fields: [f('Error', ip.error)] });
    return { layers, total: wire.length, ok: false, summary: { ah: false, esp: false, tunnel: false } };
  }
  const end = Math.min(wire.length, ip.totalLength);
  const ipLayer = add({ id: 'ip', kind: 'ip', name: 'IPv4 header', offset: 0, length: IPV4_HEADER_LEN, desc: 'Network-layer header. Routers read this; AH can authenticate it, ESP does not.' });

  let off = IPV4_HEADER_LEN;
  let proto = ip.protocol;
  let ahSeen = false;
  let espSeen = false;
  let tunnel = false;

  for (let guard = 0; guard < 4; guard++) {
    if (proto === PROTO.AH && !ahSeen && !espSeen && end - off >= AH_LEN) {
      const nh = wire[off];
      add({
        id: 'ah', kind: 'ah', name: 'AH header', offset: off, length: 12, auth: 'full',
        desc: 'Authentication Header: identifies the SA (SPI), carries the anti-replay sequence number. Adds integrity and authentication, NOT encryption.',
        fields: [
          f('Next header', `${nh} (${protoName(nh)})`),
          f('Payload length', `${wire[off + 1]}`, `= ${(wire[off + 1] + 2) * 4}-byte AH (length in 32-bit words − 2)`),
          f('Reserved', '0x0000'),
          f('SPI', hex32(r32(wire, off + 4)), 'selects the Security Association'),
          f('Sequence number', r32(wire, off + 8), 'anti-replay counter'),
        ],
      });
      add({
        id: 'ah-icv', kind: 'icv', name: 'AH ICV (authentication data)', offset: off + 12, length: ALG.ICV_LEN,
        desc: `${ALG.AUTH} over the IP header (mutable fields zeroed) + AH header + everything after it.`,
        fields: [f('ICV', toHex(wire.subarray(off + 12, off + AH_LEN)))],
      });
      ahSeen = true;
      off += AH_LEN;
      proto = nh;
      continue;
    }
    if (proto === PROTO.ESP && !espSeen && end - off >= ESP_HEADER_LEN + ALG.IV_LEN + ALG.BLOCK + ALG.ICV_LEN) {
      const ctLen = end - off - ESP_HEADER_LEN - ALG.IV_LEN - ALG.ICV_LEN;
      add({
        id: 'esp', kind: 'esp', name: 'ESP header', offset: off, length: ESP_HEADER_LEN, auth: 'full',
        desc: 'Encapsulating Security Payload header: SPI selects the SA, sequence number prevents replay.',
        fields: [f('SPI', hex32(r32(wire, off))), f('Sequence number', r32(wire, off + 4))],
      });
      add({
        id: 'iv', kind: 'iv', name: 'IV (initialisation vector)', offset: off + ESP_HEADER_LEN, length: ALG.IV_LEN, auth: 'full',
        desc: 'Fresh random value for AES-CBC: identical messages encrypt to different ciphertext.',
        fields: [f('IV', toHex(wire.subarray(off + 8, off + 24)))],
      });
      const ct = add({
        id: 'ct', kind: 'ciphertext', name: 'Encrypted payload (ciphertext)', offset: off + ESP_HEADER_LEN + ALG.IV_LEN, length: ctLen, auth: 'full', enc: true,
        desc: `${ALG.ENC} ciphertext of: data + padding + pad length + next header. Unreadable without the ESP key.`,
        fields: [f('Length', `${ctLen} bytes`, 'multiple of 16'), f('Ciphertext', toHex(wire.subarray(off + 24, off + 24 + Math.min(ctLen, 24))) + (ctLen > 24 ? '…' : ''))],
      });
      add({
        id: 'esp-icv', kind: 'icv', name: 'ESP ICV (authentication data)', offset: end - ALG.ICV_LEN, length: ALG.ICV_LEN,
        desc: `${ALG.AUTH} over ESP header + IV + ciphertext (encrypt-then-MAC). The outer IP header is NOT covered.`,
        fields: [f('ICV', toHex(wire.subarray(end - ALG.ICV_LEN, end)))],
      });
      espSeen = true;
      if (plaintext) {
        const padLen = plaintext[plaintext.length - 2];
        const nh = plaintext[plaintext.length - 1];
        const dataEnd = plaintext.length - 2 - padLen;
        let p = 0;
        const sub = (l) => add({ inside: true, auth: 'full', enc: true, bytes: plaintext.slice(l.offset, l.offset + l.length), ...l });
        if (nh === PROTO.IPIP && dataEnd >= IPV4_HEADER_LEN) {
          const inner = parseIPv4(plaintext.slice(0, IPV4_HEADER_LEN));
          tunnel = true;
          sub({
            id: 'inner-ip', kind: 'inner-ip', name: 'Original (inner) IPv4 header', offset: 0, length: IPV4_HEADER_LEN,
            desc: 'Hidden inside the ciphertext in tunnel mode: observers only see the gateway addresses.',
            fields: inner.valid ? ipFields(inner, false).map((x) => ({ ...x, cov: '' })) : [],
          });
          p = IPV4_HEADER_LEN;
        }
        sub({
          id: 'esp-payload', kind: 'payload', name: 'Application payload (decrypted)', offset: p, length: dataEnd - p,
          fields: [f('Text', printable(plaintext.subarray(p, dataEnd))), f('Length', `${dataEnd - p} bytes`)],
          desc: 'The original data, recovered by the receiver after the ICV was verified.',
        });
        sub({
          id: 'esp-pad', kind: 'trailer', name: 'ESP padding', offset: dataEnd, length: padLen,
          fields: [f('Padding', padLen ? toHexSpaced(plaintext.subarray(dataEnd, dataEnd + padLen)) : '(none)', 'bytes 01 02 03 …')],
          desc: 'Aligns the encrypted block to 16 bytes (RFC 4303 default padding 1, 2, 3, …).',
        });
        sub({ id: 'esp-padlen', kind: 'trailer', name: 'Pad length', offset: plaintext.length - 2, length: 1, fields: [f('Pad length', padLen)] });
        sub({ id: 'esp-nh', kind: 'trailer', name: 'Next header', offset: plaintext.length - 1, length: 1, fields: [f('Next header', `${nh} (${protoName(nh)})`)] });
      }
      off = end;
      proto = -1;
      break;
    }
    break;
  }

  if (off < end && proto !== -1) {
    if (proto === PROTO.IPIP && ahSeen && end - off >= IPV4_HEADER_LEN) {
      const inner = parseIPv4(wire.subarray(off, off + IPV4_HEADER_LEN));
      tunnel = true;
      add({
        id: 'inner-ip', kind: 'inner-ip', name: 'Original (inner) IPv4 header', offset: off, length: IPV4_HEADER_LEN, auth: ahSeen ? 'full' : 'none',
        desc: 'AH does not encrypt: the original header is readable, but it is authenticated.',
        fields: inner.valid ? ipFields(inner, false).map((x) => ({ ...x, cov: '' })) : [],
      });
      off += IPV4_HEADER_LEN;
    }
    add({
      id: 'payload', kind: 'payload', name: 'Application payload', offset: off, length: end - off, auth: ahSeen ? 'full' : 'none',
      desc: ahSeen ? 'Readable by anyone on the path, but any change is detected by the AH ICV.' : 'Plain data: readable and modifiable by anyone on the path.',
      fields: [f('Text', printable(wire.subarray(off, end))), f('Length', `${end - off} bytes`), f('IP protocol', `${proto} (${protoName(proto)})`, 'experimental, not TCP')],
    });
    off = end;
  } else if (!espSeen) {
    rest(off, end);
  }
  if (wire.length > end) rest(end, wire.length, 'Trailing bytes beyond IPv4 total length');

  ipLayer.auth = ahSeen ? 'partial' : 'none';
  ipLayer.fields = ipFields(ip, ahSeen);
  return { layers, total: wire.length, ok: true, summary: { ah: ahSeen, esp: espSeen, tunnel } };
}
