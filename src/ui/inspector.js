// Packet Inspector: Before IPsec / After IPsec / At attacker / At receiver.
// Everything shown comes from dissect() of the real bytes plus the receiver's recorded pipeline.

import { esc, icon } from './dom.js';
import { toHex, toHexSpaced } from '../engine/bytes.js';
import { parseIPv4 } from '../engine/ipv4.js';
import { STATE_LABEL } from '../engine/status.js';

export const STAGES = [
  { id: 'before', label: 'Before IPsec' },
  { id: 'after', label: 'After IPsec' },
  { id: 'attacker', label: 'At attacker' },
  { id: 'receiver', label: 'At receiver' },
];

const SHORT = {
  ip: 'IPv4 header', ah: 'AH header', 'ah-icv': 'AH ICV', esp: 'ESP header', iv: 'IV', ct: 'Ciphertext',
  'esp-icv': 'ESP ICV', payload: 'App payload', 'inner-ip': 'Inner IPv4', 'esp-payload': 'App payload',
  'esp-pad': 'Padding', 'esp-padlen': 'Pad len', 'esp-nh': 'Next hdr',
};
const short = (l) => SHORT[l.id] ?? l.name;
const kindClass = (l) => (l.id === 'ah-icv' ? 'k-icv-ah' : `k-${l.kind}`);
const hexClass = (l) => (l.id === 'ah-icv' ? 'h-icv' : `h-${l.kind}`);
const KIND_CHIP = { ip: 'ip', 'inner-ip': 'ip', ah: 'ah', icv: 'ok', esp: 'esp', iv: 'esp', ciphertext: 'esp', payload: 'data', trailer: 'esp', raw: 'mute' };

function authChip(l) {
  if (l.kind === 'icv') return '<span class="chip ok">integrity tag</span>';
  if (l.auth === 'full') return '<span class="chip ok">authenticated</span>';
  if (l.auth === 'partial') return '<span class="chip warn">partly authenticated</span>';
  return '<span class="chip mute">not authenticated</span>';
}
const encChip = (l) => (l.enc ? '<span class="chip esp">encrypted</span>' : '');

function covCell(c) {
  if (c === 'auth') return '<span class="chip ok">authenticated</span>';
  if (c === 'zeroed') return '<span class="chip warn">mutable · zeroed</span>';
  if (c === 'none') return '<span class="chip mute">not covered</span>';
  return '';
}

function changedBlocks(layers, changed) {
  const set = new Set();
  if (!changed?.size) return set;
  layers.forEach((l, i) => {
    if (l.inside) return;
    for (let b = l.offset; b < l.offset + l.length; b++) if (changed.has(b)) { set.add(i); break; }
  });
  return set;
}

function blocksRow(layers, changedSet, offsetBase = 0) {
  return layers
    .map((l) => {
      const idx = layers.indexOf(l) + offsetBase;
      const grow = Math.max(1, Math.pow(l.length, 0.55)).toFixed(2);
      const authBar = l.kind === 'icv' ? '' : l.auth === 'full' ? 'auth' : l.auth === 'partial' ? 'partial' : '';
      return `<div class="blk ${changedSet?.has(idx) ? 'changed' : ''}" style="flex:${grow} 1 0" title="${esc(l.name)}">
        <div class="bx ${kindClass(l)}" data-layer="${esc(l.id)}"><span class="bn">${esc(short(l))}</span><span class="bs">${l.length} B</span></div>
        <div class="bar ${authBar}"></div><div class="bar ${l.enc ? 'enc' : ''}"></div>
      </div>`;
    })
    .join('');
}

function layerDetails(layers) {
  return layers
    .map((l) => {
      const range = l.inside ? `plaintext ${l.offset}–${l.offset + l.length - 1}` : `bytes ${l.offset}–${l.offset + l.length - 1}`;
      const rows = l.fields
        .map((f) => `<tr><td>${esc(f.label)}</td><td class="v">${esc(f.value)}${f.note ? ` <span class="note">· ${esc(f.note)}</span>` : ''}</td><td class="c">${covCell(f.cov)}</td></tr>`)
        .join('');
      const cls = KIND_CHIP[l.kind] ?? 'mute';
      return `<details class="layer">
        <summary><i class="sw ${kindClass(l)}" style="background:currentColor;border:0"></i>
          <span><span class="ln">${esc(l.name)}</span> <span class="lm">${l.length} B · ${range}</span></span>
          <span class="lc"><span class="chip ${cls}">${esc(l.kind === 'icv' ? 'ICV' : l.kind.replace('-', ' '))}</span>${l.inside ? '' : authChip(l)}${encChip(l)}</span></summary>
        <div class="lb">
          ${l.desc ? `<p class="desc">${esc(l.desc)}</p>` : ''}
          ${rows ? `<table class="fields"><tbody>${rows}</tbody></table>` : ''}
          <div class="hexline">${esc(toHexSpaced(l.bytes.subarray(0, 48)))}${l.bytes.length > 48 ? ' …' : ''}</div>
        </div></details>`;
    })
    .join('');
}

function hexdump(bytes, layers, changed = null, relative = false) {
  const cls = new Array(bytes.length).fill('h-raw');
  for (const l of layers) {
    if (!relative && l.inside) continue;
    if (relative && !l.inside) continue;
    for (let i = l.offset; i < l.offset + l.length && i < bytes.length; i++) cls[i] = hexClass(l);
  }
  let out = '';
  for (let off = 0; off < bytes.length; off += 16) {
    let cells = '';
    let asc = '';
    for (let i = off; i < Math.min(off + 16, bytes.length); i++) {
      const b = bytes[i];
      const c = changed?.has(i) ? `${cls[i]} h-chg` : cls[i];
      cells += `<span class="b ${c}">${b.toString(16).padStart(2, '0')}</span> `;
      asc += b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '·';
    }
    out += `<span class="off">${off.toString(16).padStart(4, '0')}</span>${cells.padEnd(0)}${' '.repeat(Math.max(0, (16 - Math.min(16, bytes.length - off)) * 3))}<span class="asc">${asc}</span>\n`;
  }
  return `<pre class="hex">${out}</pre>`;
}

function diffSet(a, b) {
  const s = new Set();
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) s.add(i);
  return s;
}

function pipeline(receive) {
  if (!receive) return '';
  const ico = { pass: icon('check'), fail: icon('x'), skip: '–', info: 'i' };
  const steps = receive.steps
    .map(
      (s) => `<div class="pstep ${s.status}"><span class="pi">${ico[s.status] ?? ''}</span><div><div class="pt">${esc(s.title)}</div><div class="pd">${esc(s.detail)}</div></div></div>`,
    )
    .join('');
  return `<div class="pipeline"><h3>Receiver processing at ${esc(receive.verifier)}: parse → SA lookup → replay check → ICV → decrypt → policy</h3>${steps}</div>`;
}

function changesTable(changes) {
  if (!changes?.length) return '';
  return `<div class="changes"><h3>${icon('edit')} What the attacker changed</h3><table><thead><tr><th>Field</th><th>Original</th><th>Modified</th></tr></thead><tbody>
    ${changes.map((c) => `<tr><td>${esc(c.field)}</td><td class="m">${esc(c.before)}</td><td class="m after">${esc(c.after)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

export function renderInspector(state) {
  const run = state.run;
  const tabs = `<div class="tabs" role="tablist">${STAGES.map(
    (s) => `<button class="tab" role="tab" data-action="stage" data-stage="${s.id}" aria-selected="${state.stage === s.id}">${s.label}</button>`,
  ).join('')}</div>`;
  if (!run) {
    return `${tabs}<div class="empty">${icon('inspect', 22)}<p>Send a packet to inspect its headers, payload, SPI, sequence number, ICV, IV, ciphertext and checksum.</p></div>`;
  }
  const t = run.transmissions[Math.min(state.txIndex, run.transmissions.length - 1)];
  const stage = state.stage;
  let layers;
  let bytes;
  let changed = null;
  let note = '';
  let extra = '';
  let after = '';
  const origLen = run.original.bytes.length;

  if (stage === 'before') {
    layers = run.original.view.layers;
    bytes = run.original.bytes;
    note = 'The plain IPv4 packet created by Host A. Nothing protects it: anyone on the path can read or change it.';
  } else if (stage === 'after') {
    layers = t.views.after.layers;
    bytes = t.sent;
    note = run.secured
      ? `The packet as it leaves ${run.tunnel ? 'Gateway A' : 'Host A'} after ${run.cfg.protection === 'AH_ESP' ? 'AH + ESP' : run.cfg.protection} processing (${run.cfg.mode} mode).`
      : 'No IPsec: the packet is sent exactly as created.';
  } else if (stage === 'attacker') {
    const modified = t.atAttacker.modified && state.attackerSub === 'modified';
    layers = modified ? t.views.attackerModified.layers : t.views.attacker.layers;
    bytes = modified ? t.atAttacker.modified : t.atAttacker.captured;
    if (modified) changed = diffSet(t.atAttacker.captured, t.atAttacker.modified);
    const ex = t.atAttacker.exposure;
    extra = `<div class="exposure">
      <span class="chip ${ex.payloadReadable ? 'bad' : 'ok'}">${icon(ex.payloadReadable ? 'eye' : 'lock', 13)} Payload ${ex.payloadReadable ? 'READABLE' : 'not readable'}</span>
      ${ex.innerAddressesReadable === null ? '' : `<span class="chip ${ex.innerAddressesReadable ? 'bad' : 'ok'}">Original addresses ${ex.innerAddressesReadable ? 'READABLE' : 'hidden'}</span>`}
      <span class="chip mute">${ex.bytes} bytes captured on the wire</span></div>`;
    note = t.atAttacker.modified
      ? 'Mallory sits between the endpoints. Toggle between what she captured and what she forwarded.'
      : 'Mallory can always read the bytes on the wire. What she can learn depends on the protection in use.';
    after = modified ? changesTable(t.atAttacker.changes) : '';
  } else {
    layers = t.views.receiver.layers;
    bytes = t.arrived;
    note = t.dropped && t.dropped.node === 'internet'
      ? `The packet never arrived: ${t.dropped.reason}.`
      : `The packet as received at ${run.tunnel ? 'Gateway B' : 'Host B'}. The outer TTL went from ${parseIPv4(t.sent).ttl} to ${parseIPv4(t.arrived).ttl} on the way; its checksum was recomputed by each router.`;
    after = pipeline(t.receive);
  }

  const outer = layers.filter((l) => !l.inside);
  const inner = layers.filter((l) => l.inside);
  const cs = changedBlocks(layers, changed);
  const delta = bytes.length - origLen;
  const txSel = run.transmissions.length > 1
    ? `<div class="minitabs" role="group" aria-label="Transmission">${run.transmissions
        .map((x, i) => `<button data-action="tx" data-i="${i}" aria-pressed="${state.txIndex === i}">${i === 0 ? '1 · Original' : '2 · Replayed copy'}</button>`)
        .join('')}</div>`
    : '';
  const subSel = stage === 'attacker' && t.atAttacker.modified
    ? `<div class="minitabs"><button data-action="sub" data-sub="captured" aria-pressed="${state.attackerSub !== 'modified'}">Captured</button><button data-action="sub" data-sub="modified" aria-pressed="${state.attackerSub === 'modified'}">Forwarded (modified)</button></div>`
    : '';

  const body = state.view === 'hex'
    ? `<div class="hexview">${hexdump(bytes, layers, changed)}${inner.length ? `<p class="hexcap">Decrypted ESP plaintext (visible only to the receiver after the ICV passed)</p>${hexdump(concatInside(inner), inner, null, true)}` : ''}</div>`
    : `<div class="blocks" aria-label="Packet layout">${blocksRow(outer, cs)}</div>
       ${inner.length ? `<div class="nested"><div class="nt">${icon('lock', 13)} Decrypted by the receiver: this was inside the ciphertext</div><div class="blocks">${blocksRow(inner, null)}</div></div>` : ''}
       <div class="legend"><span><i style="background:var(--ok)"></i>authenticated by an ICV</span><span><i style="background:repeating-linear-gradient(90deg,var(--ok) 0 4px,transparent 4px 7px)"></i>partly (mutable fields excluded)</span><span><i style="background:var(--esp)"></i>encrypted</span></div>
       <div class="layers">${layerDetails(layers)}</div>`;

  return `${tabs}
    <div class="insp-top">
      <span class="stat">Length <b>${bytes.length} B</b></span>
      ${stage === 'before' ? '' : `<span class="stat">vs. original <b>${delta >= 0 ? '+' : ''}${delta} B</b></span>`}
      ${txSel}${subSel}
      <div class="r"><div class="minitabs" role="group" aria-label="View">
        <button data-action="view" data-view="fields" aria-pressed="${state.view !== 'hex'}">Fields</button>
        <button data-action="view" data-view="hex" aria-pressed="${state.view === 'hex'}">Hex</button></div></div>
    </div>
    <p class="note" style="padding:8px 16px 0">${esc(note)}</p>
    ${extra}
    ${body}
    ${after}`;
}

function concatInside(inner) {
  const total = inner.reduce((s, l) => s + l.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const l of inner) { out.set(l.bytes, p); p += l.length; }
  return out;
}

export { toHex, STATE_LABEL };
