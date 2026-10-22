// Runs every protection x mode x attack combination through the real simulator.
// Used by the "Verification matrix" panel and by the capability tests.

import { Simulator } from './simulator.js';

export const MATRIX_ATTACKS = Object.freeze(['sniff', 'tamper', 'forge', 'replay', 'spoof']);

export const MATRIX_CASES = Object.freeze([
  { protection: 'NONE', mode: 'transport' },
  { protection: 'AH', mode: 'transport' },
  { protection: 'AH', mode: 'tunnel' },
  { protection: 'ESP', mode: 'transport' },
  { protection: 'ESP', mode: 'tunnel' },
  { protection: 'AH_ESP', mode: 'transport' },
  { protection: 'AH_ESP', mode: 'tunnel' },
]);

export async function runMatrix({ strictSelector = false, onProgress = null } = {}) {
  const rows = [];
  let done = 0;
  for (const c of MATRIX_CASES) {
    const cells = {};
    for (const attack of MATRIX_ATTACKS) {
      const sim = new Simulator(); // fresh SAs and sequence numbers for every cell
      const run = await sim.run({ ...c, attack, strictSelector });
      const t = run.primary;
      cells[attack] = {
        outcome: t.outcome,
        accepted: t.accepted,
        payloadReadable: t.atAttacker.exposure.payloadReadable,
        droppedAt: t.dropped?.label ?? null,
        stage: t.dropped?.stage ?? null,
        reason: t.dropped?.reason ?? null,
        matchesOriginal: t.delivery?.matchesOriginal ?? null,
        deliveredSrc: t.delivery?.src ?? null,
      };
      done++;
      onProgress?.(done, MATRIX_CASES.length * MATRIX_ATTACKS.length);
    }
    rows.push({ ...c, cells });
  }
  return rows;
}
