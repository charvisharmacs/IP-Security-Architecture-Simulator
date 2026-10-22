// Security Associations (RFC 4301 section 4.4.2) - educational model.
//
// A Security Association is ONE-WAY and belongs to ONE protocol. AH and ESP therefore get separate
// SAs, each with its own SPI, its own keys, its own sequence counter and its own replay window.
// The simulator keeps two databases: the sender's (transmit counters) and the receiver's
// (replay windows). Both are created from the same negotiated parameters.

import { SimError } from './bytes.js';
import { ReplayWindow, DEFAULT_WINDOW } from './replay.js';
import { ALG } from './crypto.js';

export const PROTECTIONS = Object.freeze(['NONE', 'AH', 'ESP', 'AH_ESP']);
export const MODES = Object.freeze(['transport', 'tunnel']);

export const PROTECTION_LABEL = Object.freeze({
  NONE: 'No IPsec',
  AH: 'AH',
  ESP: 'ESP',
  AH_ESP: 'AH + ESP',
});

export function requiredProtocols(protection) {
  if (!PROTECTIONS.includes(protection)) throw new SimError('BAD_PROTECTION', `Unknown protection "${protection}"`);
  return { ah: protection === 'AH' || protection === 'AH_ESP', esp: protection === 'ESP' || protection === 'AH_ESP' };
}

export class SecurityAssociation {
  constructor({
    protocol, spi, mode, authKey, encKey = null,
    peerSrc, peerDst, trafficSrc, trafficDst, windowSize = DEFAULT_WINDOW,
  }) {
    if (protocol !== 'AH' && protocol !== 'ESP') throw new SimError('BAD_SA', 'SA protocol must be AH or ESP');
    if (!MODES.includes(mode)) throw new SimError('BAD_SA', 'SA mode must be transport or tunnel');
    if (!Number.isInteger(spi) || spi < 256 || spi > 0xffffffff) {
      throw new SimError('BAD_SA', 'SPI must be an integer in 256..2^32-1 (0-255 are reserved)');
    }
    if (!authKey || authKey.length !== ALG.AUTH_KEY_LEN) throw new SimError('BAD_SA', 'Authentication key must be 32 bytes');
    if (protocol === 'ESP' && (!encKey || encKey.length !== ALG.ENC_KEY_LEN)) {
      throw new SimError('BAD_SA', 'ESP SA needs a 16-byte AES-128 key');
    }
    this.protocol = protocol;
    this.spi = spi;
    this.mode = mode;
    this.authAlg = ALG.AUTH;
    this.encAlg = protocol === 'ESP' ? ALG.ENC : null;
    this.authKey = authKey;
    this.encKey = protocol === 'ESP' ? encKey : null;
    // Selectors: which traffic this SA protects and which outer source address it expects.
    this.peerSrc = peerSrc;
    this.peerDst = peerDst;
    this.trafficSrc = trafficSrc;
    this.trafficDst = trafficDst;
    this.txSeq = 0;
    this.replay = new ReplayWindow(windowSize);
    this.state = 'ACTIVE';
  }

  /** Next outbound sequence number. A real implementation must re-key before the 32-bit counter wraps. */
  nextSeq() {
    if (this.state !== 'ACTIVE') throw new SimError('SA_INACTIVE', `SA 0x${this.spi.toString(16)} is ${this.state}`);
    if (this.txSeq >= 0xffffffff) {
      this.state = 'EXPIRED';
      throw new SimError('SEQ_EXHAUSTED', 'Sequence number space exhausted: a new SA must be established');
    }
    return ++this.txSeq;
  }

  describe() {
    return {
      protocol: this.protocol,
      spi: this.spi,
      mode: this.mode,
      authAlg: this.authAlg,
      encAlg: this.encAlg,
      txSeq: this.txSeq,
      rxHighest: this.replay.highest,
      windowSize: this.replay.size,
      state: this.state,
      peerSrc: this.peerSrc,
      trafficSrc: this.trafficSrc,
      trafficDst: this.trafficDst,
    };
  }
}

export class SecurityAssociationDatabase {
  constructor() {
    this.entries = [];
  }

  add(sa) {
    if (this.lookup(sa.spi, sa.protocol)) throw new SimError('DUP_SA', `SPI 0x${sa.spi.toString(16)} already exists for ${sa.protocol}`);
    this.entries.push(sa);
    return sa;
  }

  /** Receiver side: find the SA from the SPI carried in the packet and the protocol (AH / ESP). */
  lookup(spi, protocol) {
    return this.entries.find((s) => s.spi === spi && s.protocol === protocol && s.state === 'ACTIVE') ?? null;
  }

  /** Sender side: select the SA for a flow. */
  find({ protocol, mode, trafficSrc, trafficDst }) {
    return (
      this.entries.find(
        (s) => s.protocol === protocol && s.mode === mode && s.trafficSrc === trafficSrc && s.trafficDst === trafficDst && s.state === 'ACTIVE',
      ) ?? null
    );
  }

  all() {
    return [...this.entries];
  }

  clear() {
    this.entries = [];
  }
}
