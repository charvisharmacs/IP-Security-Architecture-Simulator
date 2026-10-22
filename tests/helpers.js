import { establishSAs } from '../src/engine/establish.js';
import { SecurityAssociationDatabase } from '../src/engine/sa.js';
import { protect } from '../src/engine/ipsec.js';
import { makePlainPacket } from '../src/engine/ipv4.js';
import { randomBytes, encoder } from '../src/engine/bytes.js';

export const HOST_A = '192.168.1.10';
export const HOST_B = '192.168.2.20';
export const GW_A = '203.0.113.1';
export const GW_B = '198.51.100.1';
export const MESSAGE = 'Hello Host B, the password is 1234';

export const COMBOS = [
  ['AH', 'transport'], ['AH', 'tunnel'],
  ['ESP', 'transport'], ['ESP', 'tunnel'],
  ['AH_ESP', 'transport'], ['AH_ESP', 'tunnel'],
];

export const plain = (text = MESSAGE, ttl = 64) =>
  makePlainPacket({ src: HOST_A, dst: HOST_B, payload: encoder.encode(text), ttl, id: 0x1001 });

/** Established SAs plus a receiving endpoint, as the simulator would set them up. */
export async function setup(protection, mode, { strictSelector = false } = {}) {
  const est = await establishSAs({
    protection, mode, hostSrc: HOST_A, hostDst: HOST_B, gwSrc: GW_A, gwDst: GW_B, psk: randomBytes(32),
  });
  const sad = new SecurityAssociationDatabase();
  Object.values(est.rx).forEach((s) => sad.add(s));
  return {
    protection, mode, est, sas: est.tx,
    endpoint: { name: 'Receiver', sad, policy: { protection, mode }, strictSelector },
  };
}

export const send = (ctx, packet = plain(), id = 7) =>
  protect({
    packet, protection: ctx.protection, mode: ctx.mode, sas: ctx.sas, tunnel: { src: GW_A, dst: GW_B }, id,
  });
