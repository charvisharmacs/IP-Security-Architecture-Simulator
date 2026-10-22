// Right-hand and lower panels. Every value displayed is read from the simulator's results.

import { esc, icon } from './dom.js';
import { STATE_LABEL } from '../engine/status.js';
import { PROTECTION_LABEL } from '../engine/sa.js';
import { ATTACK_LABEL } from '../engine/attacker.js';
import { CAPABILITIES, CAPABILITY_NOTES, COLUMNS } from '../engine/capabilities.js';
import { MATRIX_ATTACKS } from '../engine/matrix.js';
import { hex32 } from '../engine/bytes.js';

export const currentTx = (state) =>
  state.run ? state.run.transmissions[Math.min(state.txIndex, state.run.transmissions.length - 1)] : null;

const pad4 = (n) => String(n).padStart(4, '0');

// ---------------------------------------------------------------------------------------------
// Security status
// ---------------------------------------------------------------------------------------------
export function renderStatus(state) {
  const t = currentTx(state);
  const idle = !t;
  let verdict;
  if (idle) {
    verdict = `<div class="verdict idle"><div class="vi">${icon('shield')}</div><div><div class="big">Waiting for a packet</div><div class="why">Press “Send packet” to run the simulation.</div></div></div>`;
  } else if (t.accepted) {
    const lab = t.delivery && !t.delivery.matchesOriginal ? ' (content or source differs from what Host A sent)' : '';
    verdict = `<div class="verdict ok"><div class="vi">${icon('check')}</div><div><div class="big">PACKET ACCEPTED</div><div class="why">Delivered to Host B${esc(lab)}.</div></div></div>`;
  } else {
    const replay = t.dropped?.stage === 'Anti-replay check';
    verdict = `<div class="verdict bad"><div class="vi">${icon('x')}</div><div><div class="big">${replay ? 'REPLAY DETECTED · ' : ''}PACKET REJECTED</div><div class="why">Dropped at ${esc(t.dropped?.label ?? '?')} · ${esc(t.dropped?.stage ?? '')}: ${esc(t.dropped?.reason ?? '')}</div></div></div>`;
  }
  const s = t?.status;
  const row = (name, st, detail, label) => `<div class="srow"><span class="n">${name}</span><span class="st ${st ?? 'idle'}">${esc(label ?? STATE_LABEL[st] ?? '—')}</span><span class="d">${esc(detail ?? '')}</span></div>`;
  const rows = idle
    ? ['Confidentiality', 'Authentication', 'Integrity', 'Anti-replay'].map((n) => row(n, 'idle', 'Not evaluated yet', '—')).join('') + row('IP header coverage', 'idle', 'Not evaluated yet', '—')
    : row('Confidentiality', s.confidentiality.state, s.confidentiality.detail)
      + row('Authentication', s.authentication.state, s.authentication.detail)
      + row('Integrity', s.integrity.state, s.integrity.detail)
      + row('Anti-replay', s.antiReplay.state, s.antiReplay.detail)
      + row('IP header coverage', s.headerCoverage.state === 'verified' ? 'verified' : 'not-provided', s.headerCoverage.text, s.headerCoverage.state === 'verified' ? '✓ AUTHENTICATED' : 'NOT COVERED');
  return `<div class="card-h"><h2>${icon('shield')} Security status</h2></div>${verdict}${rows}`;
}

// ---------------------------------------------------------------------------------------------
// Results (current packet)
// ---------------------------------------------------------------------------------------------
const OUTCOME_TEXT = {
  normal: ['—', ''],
  defended: ['DEFENDED', 'ok'],
  succeeded: ['ATTACK SUCCEEDED', 'bad'],
  'no-effect': ['ACCEPTED · NO EFFECT', 'warn'],
};

export function renderResult(state) {
  const run = state.run;
  const t = currentTx(state);
  if (!run) {
    return `<div class="card-h"><h2>${icon('list')} Result</h2></div><div class="empty">${icon('flag', 22)}<p>No packet sent yet.</p></div>`;
  }
  const chip = (st, label) => `<span class="chip ${st === 'verified' ? 'ok' : st === 'failed' ? 'bad' : 'mute'}">${label} ${st === 'verified' ? '✓' : st === 'failed' ? '✗' : st === 'not-provided' ? 'n/a' : '—'}</span>`;
  const s = t.status;
  let outcome = OUTCOME_TEXT[t.outcome] ?? ['—', ''];
  if (t.outcome === 'sniff') outcome = t.atAttacker.exposure.payloadReadable ? ['PAYLOAD EXPOSED', 'bad'] : ['PAYLOAD PROTECTED', 'ok'];
  const attackName = t.injected ? 'Replay' : ATTACK_LABEL[t.attack] ?? '—';
  const acc = t.accepted;
  return `<div class="card-h"><h2>${icon('list')} Result</h2><span class="r"><span class="sub">${esc(t.label)}</span></span></div>
    <div class="res-head"><span class="pkt-no">#${pad4(run.packetNo)}</span><span class="chip ${acc ? 'ok' : 'bad'}" style="font-size:13px;padding:4px 12px">${acc ? '✓ ACCEPTED' : '✗ REJECTED'}</span></div>
    <dl class="kv">
      <dt>Protocol</dt><dd>${esc(PROTECTION_LABEL[run.cfg.protection])}</dd>
      <dt>Mode</dt><dd>${run.secured ? esc(run.cfg.mode[0].toUpperCase() + run.cfg.mode.slice(1)) : '—'}</dd>
      <dt>Attack</dt><dd>${esc(attackName)}</dd>
      <dt>Attack outcome</dt><dd class="${outcome[1] === 'ok' ? 'yes' : outcome[1] === 'bad' ? 'r-bad' : ''}" style="${outcome[1] === 'bad' ? 'color:var(--bad)' : outcome[1] === 'warn' ? 'color:var(--warn)' : ''}">${esc(outcome[0])}</dd>
      <dt>Dropped at</dt><dd>${t.dropped ? esc(t.dropped.label) : '—'}</dd>
      <dt>Rejected by</dt><dd>${t.dropped ? esc(t.dropped.stage) : '—'}</dd>
      <dt>Wire size</dt><dd>${t.sent.length} B</dd>
      <dt>IPsec overhead</dt><dd>+${run.overhead} B</dd>
      <dt>Sequence</dt><dd>${[t.receive?.seqs?.ah && `AH ${t.receive.seqs.ah}`, t.receive?.seqs?.esp && `ESP ${t.receive.seqs.esp}`].filter(Boolean).join(' · ') || '—'}</dd>
    </dl>
    <div class="res-chips">${chip(s.confidentiality.state, 'Confidentiality')}${chip(s.integrity.state, 'Integrity')}${chip(s.authentication.state, 'Authentication')}${chip(s.antiReplay.state, 'Replay')}</div>`;
}

// ---------------------------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------------------------
export function renderReplay(state) {
  const sas = state.sim.describeSAs();
  const t = currentTx(state);
  const head = `<div class="card-h"><h2>${icon('repeat')} Anti-replay window</h2><span class="r"><span class="sub">32-packet sliding window</span></span></div>`;
  if (!sas.length) {
    const msg = state.run && !state.run.secured
      ? 'No IPsec: there are no sequence numbers, so a replayed packet is simply accepted again.'
      : 'Sequence numbers appear here once AH or ESP traffic has been sent.';
    return `${head}<div class="empty" style="padding:20px 16px">${icon('repeat', 22)}<p>${msg}</p></div>`;
  }
  return head + sas.map((sa) => {
    const hi = sa.rxHighest;
    const size = 32;
    const start = Math.max(1, hi - size + 1);
    const seen = new Set(sa.window?.cells.filter((c) => c.accepted).map((c) => c.seq));
    const chk = t?.receive?.checks?.[sa.protocol.toLowerCase()];
    const testSeq = chk && chk.spi === sa.spi ? chk.seq : null;
    let cells = '';
    for (let i = 0; i < size; i++) {
      const seq = start + i;
      const cls = [seen.has(seq) ? 'acc' : '', seq === hi && hi > 0 ? 'top' : '', testSeq === seq && chk.replay === 'fail' ? 'test' : ''].join(' ');
      cells += `<div class="cell ${cls}" title="Sequence ${seq}${seen.has(seq) ? ' · accepted' : ''}">${seq <= 999 ? seq : ''}</div>`;
    }
    let note = `Highest accepted: ${hi || '—'} · green = accepted, empty = not yet seen`;
    let nc = '';
    if (chk && chk.spi === sa.spi) {
      if (chk.replay === 'fail') { note = `REPLAY DETECTED: ${chk.replayReason.replace('REPLAY DETECTED: ', '')} → PACKET REJECTED`; nc = 'bad'; }
      else if (chk.replay === 'pass') { note = `Sequence ${chk.seq} checked: ${chk.replayReason}`; nc = 'ok'; }
    }
    return `<div class="rw"><div class="rt"><b><span class="chip ${sa.protocol === 'AH' ? 'ah' : 'esp'}">${sa.protocol}</span> &nbsp;SPI ${hex32(sa.spi)}</b><span>highest ${hi}</span></div>
      <div class="cells">${cells}</div><div class="rn ${nc}">${esc(note)}</div></div>`;
  }).join('');
}

// ---------------------------------------------------------------------------------------------
// Event log + history
// ---------------------------------------------------------------------------------------------
export function renderLog(state) {
  const items = state.logAll.slice(-500);
  const body = items.length
    ? items.map((e) => (e.sep
      ? `<div class="lsep">${esc(e.text)}</div>`
      : `<div class="ll ${e.level}"><span class="n">${e.n}</span><span class="d"></span><span class="t">${esc(e.text)}</span><span class="w">${e.node ? esc(e.node) : ''}</span></div>`)).join('')
    : `<div class="empty">${icon('list', 22)}<p>Events appear here as packets are created, protected, transmitted and verified.</p></div>`;
  return `<div class="card-h"><h2>${icon('list')} Event log</h2><span class="r"><button class="btn sm ghost" data-action="clear-log">Clear</button></span></div><div class="logbox" id="logbox">${body}</div>`;
}

export function renderHistory(state) {
  const rows = state.history.length
    ? state.history.slice().reverse().map((h) => `<tr>
        <td class="mono">#${pad4(h.no)}</td><td>${esc(h.protocol)}</td><td>${esc(h.mode)}</td><td>${esc(h.attack)}</td>
        <td class="mono">${h.size} B</td><td class="mono">+${h.overhead} B</td><td>${esc(h.dropped)}</td>
        <td><span class="chip ${h.accepted ? 'ok' : 'bad'}">${h.accepted ? '✓ Accepted' : '✗ Rejected'}</span></td></tr>`).join('')
    : `<tr><td colspan="8" class="wrap" style="text-align:center;color:var(--text-3);padding:26px">No packets yet.</td></tr>`;
  return `<div class="card-h"><h2>${icon('table')} Packet history</h2><span class="r"><span class="sub">${state.history.length} packet${state.history.length === 1 ? '' : 's'}</span></span></div>
    <div class="scrollx" style="max-height:380px;overflow:auto"><table class="tbl"><thead><tr><th>#</th><th>Protocol</th><th>Mode</th><th>Attack</th><th>Size</th><th>Overhead</th><th>Dropped at</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ---------------------------------------------------------------------------------------------
// Security Associations
// ---------------------------------------------------------------------------------------------
export function renderSaMini(state) {
  const sas = state.sim.describeSAs();
  const items = sas.length
    ? sas.map((sa) => `<div class="sa-item"><div class="h"><span class="chip ${sa.protocol === 'AH' ? 'ah' : 'esp'}">${sa.protocol}</span><b class="mono">${hex32(sa.spi)}</b><span class="chip mute" style="margin-left:auto">${esc(sa.state)}</span></div>
        <div class="m"><b>${esc(sa.mode)}</b> · ${esc(sa.authAlg)}${sa.encAlg ? ` · ${esc(sa.encAlg)}` : ''}</div>
        <div class="m">tx seq <b>${sa.txSeq}</b> · rx highest <b>${sa.rxHighest}</b> · window ${sa.window?.size ?? 32}</div></div>`).join('')
    : `<p class="note">No Security Associations yet. They are created automatically (simplified establishment) the first time a protected packet is sent. AH and ESP each get their own SA.</p>`;
  return `<div class="card-h"><h2>${icon('key')} Security Associations</h2><span class="r"><span class="sub">${sas.length} active</span></span></div><div class="sa-mini">${items}</div>
    <div style="padding:0 16px 16px"><button class="btn sm block" data-action="rekey">${icon('key', 14)} Re-key (discard all SAs)</button></div>`;
}

export function renderEstablish(state) {
  const rec = state.estView ?? state.sim.establishments.at(-1) ?? null;
  const steps = rec
    ? rec.steps.map((s, i) => `<div class="step ${i < state.estShown ? 'on' : ''}"><div class="sn"><span class="num">${i + 1}</span><span class="actor">${esc(s.actor)}</span></div><div class="st">${esc(s.title)}</div><div class="sd">${esc(s.detail)}</div></div>`).join('')
    : `<div class="empty" style="grid-column:1/-1">${icon('key', 22)}<p>Send a protected packet, or press “Run establishment”, to see the steps.</p></div>`;
  const sas = state.sim.describeSAs();
  const reveal = state.revealKeys;
  const key = (k) => (k ? `<span class="keycell ${reveal ? '' : 'hidden'}" title="Demo key, generated for this session">${esc(reveal ? k : k.slice(0, 24) + '…')}</span>` : '—');
  const table = sas.length
    ? `<div class="scrollx"><table class="tbl"><thead><tr><th>Protocol</th><th>SPI</th><th>Mode</th><th>Authentication</th><th>Encryption</th><th>Auth key</th><th>Enc key</th><th>Tx seq</th><th>Rx highest</th><th>State</th></tr></thead><tbody>
      ${sas.map((sa) => `<tr><td><span class="chip ${sa.protocol === 'AH' ? 'ah' : 'esp'}">${sa.protocol}</span></td><td class="mono">${hex32(sa.spi)}</td><td>${esc(sa.mode)}</td><td>${esc(sa.authAlg)}</td><td>${esc(sa.encAlg ?? '—')}</td><td>${key(sa.authKey)}</td><td>${key(sa.encKey)}</td><td class="mono">${sa.txSeq}</td><td class="mono">${sa.rxHighest}</td><td><span class="chip ok">${esc(sa.state)}</span></td></tr>`).join('')}
      </tbody></table></div>`
    : `<p class="note" style="padding:0 16px 16px">The SA database is empty.</p>`;
  return `<div class="card-h"><h2>${icon('key')} Simplified SA establishment</h2><span class="chip warn">Educational model · not a full IKEv2 implementation</span>
      <span class="r"><label class="switch" style="align-items:center"><input type="checkbox" data-action="reveal" ${reveal ? 'checked' : ''}><span class="t">Reveal demo keys</span></label>
      <button class="btn sm" data-action="establish">${icon('play', 13)} Run establishment</button></span></div>
    <p class="est-disclaimer" style="margin-top:14px">Real cryptography is used for the key steps (ephemeral ECDH P-256, pre-shared-key authentication over the transcript, HKDF-SHA-256), but IKEv2 message formats, cookies, certificates, multiple proposals, NAT traversal, lifetimes and re-keying are <b>not</b> implemented. Keys are generated per session for demonstration only.</p>
    <div class="steps">${steps}</div>
    <div style="padding:0 16px 8px"><span class="label">Security Association Database (sender and receiver ends)</span></div>${table}`;
}

// ---------------------------------------------------------------------------------------------
// Comparison + verification matrix
// ---------------------------------------------------------------------------------------------
const COL_LABEL = { NONE: 'No IPsec', AH: 'AH', ESP: 'ESP', AH_ESP: 'AH + ESP' };
const COL_CLASS = { NONE: 'col-none', AH: 'col-ah', ESP: 'col-esp', AH_ESP: 'col-both' };

export function renderComparison() {
  const cell = (c) => `<span class="cc ${c.v === 'yes' ? 'yes' : c.v === 'partial' ? 'part' : 'no'}">${c.v === 'yes' ? icon('check', 14) : c.v === 'partial' ? icon('alert', 14) : icon('x', 14)} ${esc(c.text)}</span>`;
  return `<div class="card-h"><h2>${icon('table')} AH vs ESP comparison</h2><span class="r"><span class="sub">checked against the simulator by the test suite</span></span></div>
    <div class="scrollx"><table class="tbl cmp"><thead><tr><th>Feature</th>${COLUMNS.map((c) => `<th class="${COL_CLASS[c]}">${COL_LABEL[c]}</th>`).join('')}</tr></thead>
    <tbody>${CAPABILITIES.map((row) => `<tr><td>${esc(row.feature)}</td>${COLUMNS.map((c) => `<td>${cell(row[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
    <div style="padding:12px 16px 16px" class="note">${CAPABILITY_NOTES.map((n) => `<div>• ${esc(n)}</div>`).join('')}</div>`;
}

const MCELL = (c, attack) => {
  if (!c) return '';
  if (attack === 'sniff') {
    return c.payloadReadable
      ? '<div class="mcell"><span class="m-leaked">✗ Payload readable</span><small>captured bytes contain the message</small></div>'
      : '<div class="mcell"><span class="m-protected">✓ Payload hidden</span><small>only ciphertext visible</small></div>';
  }
  if (c.outcome === 'defended') return `<div class="mcell"><span class="m-defended">✓ Rejected</span><small>at ${esc(c.droppedAt)} · ${esc(c.stage)}</small></div>`;
  if (c.outcome === 'no-effect') return '<div class="mcell"><span class="m-no-effect">≈ Accepted, no effect</span><small>outer header not covered; inner packet unchanged</small></div>';
  const extra = attack === 'spoof' && c.deliveredSrc ? `delivered with source ${c.deliveredSrc}` : attack === 'replay' ? 'duplicate delivered again' : attack === 'forge' ? 'forged packet delivered' : 'modified data delivered';
  return `<div class="mcell"><span class="m-succeeded">✗ Attack succeeded</span><small>${esc(extra)}</small></div>`;
};

export function renderMatrix(state) {
  const m = state.matrix;
  const body = m?.rows
    ? `<div class="scrollx"><table class="tbl"><thead><tr><th>Protection</th><th>Mode</th>${MATRIX_ATTACKS.map((a) => `<th>${a === 'spoof' ? 'Modify source IP' : ATTACK_LABEL[a]}</th>`).join('')}</tr></thead><tbody>
      ${m.rows.map((r) => `<tr><td><b>${esc(COL_LABEL[r.protection])}</b></td><td>${r.protection === 'NONE' ? '—' : esc(r.mode)}</td>${MATRIX_ATTACKS.map((a) => `<td>${MCELL(r.cells[a], a)}</td>`).join('')}</tr>`).join('')}
      </tbody></table></div><p class="note" style="padding:12px 16px 16px">Each cell is a separate simulation with fresh keys. Strict selector check was <b>${m.strict ? 'ON' : 'OFF'}</b>. “≈ Accepted, no effect” means the outer header was altered but the authenticated inner packet that Host B received is identical to what Host A sent.</p>`
    : `<div class="empty">${icon('grid', 22)}<p>${m?.running ? `Running ${m.done} / ${m.total} simulations…` : 'Runs every protection × mode × attack combination through the real simulator and shows what each one actually does.'}</p></div>`;
  return `<div class="card-h"><h2>${icon('grid')} Verification matrix</h2><span class="r"><span class="sub">35 live simulations</span><button class="btn sm primary" data-action="matrix" ${m?.running ? 'disabled' : ''}>${icon('play', 13)} Run all combinations</button></span></div>${body}`;
}
