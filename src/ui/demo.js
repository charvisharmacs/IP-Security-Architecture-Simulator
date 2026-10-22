// Guided demo: nine steps. Each step applies a configuration, runs the real simulator, and then
// states the outcome that was MEASURED (never a hard-coded claim).

import { esc, icon } from './dom.js';

const last = (runs) => runs[runs.length - 1];
const R = (label, text, ok) => ({ label, text, ok });

export const DEMO_STEPS = [
  {
    title: 'Baseline: no IPsec',
    intro: 'Host A sends an ordinary IP packet. Nothing is authenticated or encrypted.',
    bullets: ['An attacker on the Internet sniffs the packet and reads the message.', 'This is the problem IPsec solves.'],
    cfgs: [{ protection: 'NONE', mode: 'transport', attack: 'sniff' }],
    results: (runs) => [R('Attacker can read the message', last(runs).primary.atAttacker.exposure.payloadReadable ? 'Yes: payload exposed' : 'No', !last(runs).primary.atAttacker.exposure.payloadReadable)],
  },
  {
    title: 'AH: authentication and integrity',
    intro: 'The Authentication Header adds an ICV (HMAC-SHA-256-128) over the packet.',
    bullets: ['The message stays readable: AH does not encrypt.', 'Any change to the packet will break the ICV.'],
    cfgs: [{ protection: 'AH', mode: 'transport', attack: 'sniff' }],
    results: (runs) => {
      const t = last(runs).primary;
      return [R('Attacker can read the message', t.atAttacker.exposure.payloadReadable ? 'Yes (AH has no confidentiality)' : 'No', !t.atAttacker.exposure.payloadReadable), R('Packet accepted by receiver', t.accepted ? 'Yes, ICV verified' : 'No', t.accepted)];
    },
  },
  {
    title: 'ESP: confidentiality',
    intro: 'Encapsulating Security Payload encrypts the payload with AES-128-CBC and adds its own ICV.',
    bullets: ['The sniffed packet shows only ciphertext.', 'Only the receiver, who holds the SA key, can decrypt.'],
    cfgs: [{ protection: 'ESP', mode: 'transport', attack: 'sniff' }],
    results: (runs) => {
      const t = last(runs).primary;
      return [R('Attacker can read the message', t.atAttacker.exposure.payloadReadable ? 'Yes' : 'No: only ciphertext visible', !t.atAttacker.exposure.payloadReadable), R('Receiver decrypted the message', t.accepted ? 'Yes' : 'No', t.accepted)];
    },
  },
  {
    title: 'Tamper attack versus AH',
    intro: 'Mallory flips a bit in the payload and forwards the packet.',
    bullets: ['The receiver recomputes the ICV; it no longer matches.', 'The packet is dropped by the verifying node.'],
    cfgs: [{ protection: 'AH', mode: 'transport', attack: 'tamper' }],
    results: (runs) => {
      const t = last(runs).primary;
      return [R('Outcome', t.accepted ? 'Modified data delivered' : `Rejected at ${t.dropped.label}: ${t.dropped.stage}`, !t.accepted)];
    },
  },
  {
    title: 'Replay attack versus ESP',
    intro: 'Mallory records a valid packet and sends a copy later.',
    bullets: ['The copy has valid ICV, but its sequence number was already used.', 'The 32-packet anti-replay window rejects it.'],
    cfgs: [{ protection: 'ESP', mode: 'transport', attack: 'replay' }],
    results: (runs) => {
      const r = last(runs);
      const first = r.transmissions[0];
      const dup = r.transmissions[1];
      return [R('Original packet', first.accepted ? 'Accepted' : 'Rejected', first.accepted), R('Replayed copy', dup && !dup.accepted ? `Rejected: ${dup.dropped.stage}` : 'Accepted again', !!dup && !dup.accepted)];
    },
  },
  {
    title: 'Tunnel mode',
    intro: 'Gateways protect traffic between two sites. The whole original IP packet becomes the payload.',
    bullets: ['The Internet only sees Gateway A → Gateway B.', 'Inner addresses and payload are hidden by ESP.'],
    cfgs: [{ protection: 'ESP', mode: 'tunnel', attack: 'sniff' }],
    results: (runs) => {
      const t = last(runs).primary;
      const e = t.atAttacker.exposure;
      return [R('Inner payload visible to attacker', e.payloadReadable ? 'Yes' : 'No', !e.payloadReadable), R('Delivered to Host B', t.accepted ? 'Yes, after Gateway B decapsulation' : 'No', t.accepted)];
    },
  },
  {
    title: 'AH + ESP together',
    intro: 'ESP is applied first, then AH over the result. You get encryption and header-level authentication.',
    bullets: ['Two Security Associations are used, each with its own SPI and sequence counter.', 'The receiver verifies AH first, then ESP.'],
    cfgs: [{ protection: 'AH_ESP', mode: 'transport', attack: 'tamper' }],
    results: (runs) => {
      const t = last(runs).primary;
      return [R('Outcome', t.accepted ? 'Modified data delivered' : `Rejected at ${t.dropped.label}: ${t.dropped.stage}`, !t.accepted)];
    },
  },
  {
    title: 'Source-IP modification',
    intro: 'Mallory rewrites the source address in the outer IP header. Compare ESP and AH in transport mode.',
    bullets: ['ESP does not cover the outer IP header; AH does.', 'This is a real, measured difference between the protocols.'],
    cfgs: [{ protection: 'ESP', mode: 'transport', attack: 'spoof' }, { protection: 'AH', mode: 'transport', attack: 'spoof' }],
    results: (runs) => runs.map((r, i) => {
      const t = r.primary;
      const name = i === 0 ? 'ESP transport' : 'AH transport';
      return R(name, t.accepted ? `Accepted, delivered source ${t.delivery?.src ?? '?'}` : `Rejected: ${t.dropped.stage}`, !t.accepted);
    }),
  },
  {
    title: 'Summary: verify everything',
    intro: 'Run the verification matrix to see every protection × mode × attack combination, each a separate simulation.',
    bullets: ['Use the “Run all combinations” button below, or the comparison table above it.', 'Then walk through the packet inspector for any case.'],
    cfgs: [],
    results: () => [],
  },
];

export function renderDemo(state) {
  const d = state.demo;
  if (!d.open) return '';
  const s = DEMO_STEPS[d.step];
  const dots = DEMO_STEPS.map((_, i) => `<i class="${i === d.step ? 'on' : i < d.step ? 'done' : ''}"></i>`).join('');
  const results = d.results?.length
    ? `<div class="demo-results">${d.results.map((r) => `<div class="demo-res"><span>${esc(r.label)}</span><span class="r" style="color:var(--${r.ok ? 'ok' : 'bad'})">${esc(r.text)}</span></div>`).join('')}</div>`
    : '';
  return `<div class="card-h"><h2>${icon('book')} Guided demo · step ${d.step + 1} of ${DEMO_STEPS.length}</h2><span class="r"><div class="demo-dots">${dots}</div><button class="btn sm ghost" data-action="demo-close">Close</button></span></div>
    <div class="demo-body"><h3>${esc(s.title)}</h3><p>${esc(s.intro)}</p><ul>${s.bullets.map((b) => `<li>${esc(b)}</li>`).join('')}</ul>${results}</div>
    <div class="demo-foot"><button class="btn sm" data-action="demo-prev" ${d.step === 0 ? 'disabled' : ''}>${icon('prev', 13)} Back</button>
      ${s.cfgs.length ? `<button class="btn sm primary" data-action="demo-run" ${state.busy ? 'disabled' : ''}>${icon('play', 13)} Run this step</button>` : ''}
      <span class="sp"></span><button class="btn sm" data-action="demo-next" ${d.step === DEMO_STEPS.length - 1 ? 'disabled' : ''}>Next ${icon('next', 13)}</button></div>`;
}
