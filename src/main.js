import './styles/main.css';
import { $, $$, esc, icon, sleep } from './ui/dom.js';
import { Simulator, DEFAULT_CONFIG, MAX_PAYLOAD, NODE_LABEL } from './engine/simulator.js';
import { PROTECTION_LABEL } from './engine/sa.js';
import { ATTACKS, ATTACK_LABEL } from './engine/attacker.js';
import { runMatrix, MATRIX_CASES, MATRIX_ATTACKS } from './engine/matrix.js';
import { parseIPv4Address } from './engine/bytes.js';
import { createTopology, drawTopology } from './ui/topology.js';
import { renderInspector } from './ui/inspector.js';
import * as P from './ui/panels.js';
import { DEMO_STEPS, renderDemo } from './ui/demo.js';

const ATTACK_INFO = {
  none: ['user', 'No attack', 'Normal transmission'],
  sniff: ['eye', 'Sniff', 'Capture the packet and try to read it'],
  tamper: ['edit', 'Tamper', 'Change the data in transit'],
  forge: ['user', 'Forge', 'Inject a packet made with guessed keys'],
  replay: ['repeat', 'Replay', 'Send a recorded packet again'],
  spoof: ['swap', 'Modify source IP', 'Rewrite the outer source address'],
};
const PROTS = [['NONE', 'No IPsec'], ['AH', 'AH'], ['ESP', 'ESP'], ['AH_ESP', 'AH + ESP']];

const state = {
  sim: new Simulator(),
  cfg: { ...DEFAULT_CONFIG },
  speed: 'normal',
  run: null, txIndex: 0, stage: 'before', view: 'fields', attackerSub: 'captured',
  logAll: [], history: [], matrix: null, estView: null, estShown: 99, revealKeys: false,
  busy: false, demo: { open: false, step: 0, results: [] },
};
const ipOk = (s) => { try { parseIPv4Address(s); return true; } catch { return false; } };
let topo;

// ---------- config panel (built once) ----------
function buildConfig() {
  $('#cfg').innerHTML = `<div class="card-h"><h2>${icon('layers')} Configuration</h2></div><div class="card-b">
  <div class="group"><span class="label">Protection</span><div class="seg" id="prot">${PROTS.map(([v, l]) => `<button data-action="prot" data-protection="${v}">${l}</button>`).join('')}</div></div>
  <div class="group"><span class="label">Mode</span><div class="seg two" id="mode"><button data-action="mode" data-mode="transport">Transport</button><button data-action="mode" data-mode="tunnel">Tunnel</button></div><div class="note" id="mode-note" style="margin-top:6px"></div></div>
  <div class="group row2"><div><label class="label" for="srcIp">Source IP</label><input class="input mono" id="srcIp" autocomplete="off"></div><div><label class="label" for="dstIp">Destination IP</label><input class="input mono" id="dstIp" autocomplete="off"></div></div>
  <div class="field-err" id="ip-err"></div>
  <div class="group"><label class="label" for="payload">Application payload</label><textarea class="input" id="payload" maxlength="${MAX_PAYLOAD}"></textarea><div class="hint"><span>Sent as IP protocol 253 (experimental)</span><span id="plen"></span></div></div>
  <div class="group"><span class="label">Attack</span><div class="attacks" id="attacks">${ATTACKS.map((a) => `<button class="attack" data-action="attack" data-attack="${a}"><span>${icon(ATTACK_INFO[a][0], 16)}</span><span><div class="t">${ATTACK_INFO[a][1]}</div><div class="d">${ATTACK_INFO[a][2]}</div></span></button>`).join('')}</div></div>
  <div class="group" id="spoof-g" hidden><label class="label" for="spoofIp">Spoofed source IP</label><input class="input mono" id="spoofIp" autocomplete="off"></div>
  <div class="group"><label class="switch"><input type="checkbox" id="strict"><span><div class="t">Strict selector check</div><div class="d">Receiver also checks the inner source/destination against the SA. Off by default (educational).</div></span></label></div>
  <div class="group row2"><div><label class="label" for="speed">Animation</label><select class="select" id="speed"><option value="normal">Normal</option><option value="fast">Fast</option><option value="instant">Instant</option></select></div><div></div></div>
  <div style="display:grid;gap:8px"><button class="btn primary block" data-action="send" id="btn-send">${icon('send', 15)} Send packet</button><button class="btn block" data-action="reset">${icon('reset', 15)} Reset simulation</button></div></div>`;
  $('#brand-mark').innerHTML = icon('shield');
  $('#btn-demo').innerHTML = `${icon('book', 14)} Guided demo`;
  $('#topo-card').innerHTML = `<div class="card-h"><h2>${icon('route')} Network topology</h2><span class="r"><span class="sub" id="topo-sub"></span></span></div><div id="topo"></div><div class="caption" id="caption">${icon('info', 16)}<span>Choose a configuration and press “Send packet”.</span></div><ol class="journey" id="journey"></ol><div class="demo" id="demo" hidden style="border-top:1px solid var(--border)"></div>`;
  topo = createTopology($('#topo'), onFrame);
  syncConfig();
}

function syncConfig() {
  const c = state.cfg;
  $$('#prot button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.protection === c.protection)));
  $$('#mode button').forEach((b) => { b.setAttribute('aria-pressed', String(b.dataset.mode === c.mode && c.protection !== 'NONE')); b.disabled = c.protection === 'NONE'; });
  $('#mode-note').textContent = c.protection === 'NONE' ? 'Mode does not apply without IPsec.' : c.mode === 'tunnel' ? 'Gateways protect the whole original packet (5 nodes).' : 'Hosts protect the payload end to end (3 nodes).';
  $$('#attacks .attack').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.attack === c.attack)));
  $('#spoof-g').hidden = c.attack !== 'spoof';
  for (const id of ['srcIp', 'dstIp', 'payload', 'spoofIp']) if (document.activeElement !== $('#' + id)) $('#' + id).value = c[id];
  $('#strict').checked = c.strictSelector;
  $('#speed').value = state.speed;
  $('#plen').textContent = `${new TextEncoder().encode(c.payload).length} / ${MAX_PAYLOAD} bytes`;
  validate();
  if (!state.busy) { topo.draw(c); $('#topo-sub').textContent = c.protection === 'NONE' ? 'No IPsec' : `${PROTECTION_LABEL[c.protection]} · ${c.mode}`; }
}

function validate() {
  const c = state.cfg; const errs = [];
  const bad = { srcIp: !ipOk(c.srcIp), dstIp: !ipOk(c.dstIp), spoofIp: c.attack === 'spoof' && !ipOk(c.spoofIp) };
  if (bad.srcIp || bad.dstIp) errs.push('Enter valid IPv4 addresses (for example 192.168.1.10).');
  else if (c.srcIp === c.dstIp) { errs.push('Source and destination must differ.'); bad.dstIp = true; }
  if (bad.spoofIp) errs.push('Spoofed source must be a valid IPv4 address.');
  if (!c.payload.length) errs.push('Payload must not be empty.');
  for (const k of Object.keys(bad)) $('#' + k).classList.toggle('invalid', bad[k]);
  $('#payload').classList.toggle('invalid', !c.payload.length);
  $('#ip-err').textContent = errs.join(' ');
  state.valid = errs.length === 0;
  $('#btn-send').disabled = !state.valid || state.busy;
}

// ---------- rendering ----------
function renderAll() {
  $('#status').innerHTML = P.renderStatus(state);
  $('#result').innerHTML = P.renderResult(state);
  $('#insp').innerHTML = renderInspector(state);
  $('#sa').innerHTML = P.renderSaMini(state);
  $('#replay').innerHTML = P.renderReplay(state);
  $('#log').innerHTML = P.renderLog(state);
  $('#est').innerHTML = P.renderEstablish(state);
  $('#cmp').innerHTML = P.renderComparison();
  $('#mtx').innerHTML = P.renderMatrix(state);
  const d = $('#demo'); d.hidden = !state.demo.open; d.innerHTML = renderDemo(state);
  const lb = $('#logbox'); if (lb) lb.scrollTop = lb.scrollHeight;
  renderJourney(-1);
}
const renderSome = (...ids) => {
  const f = { status: P.renderStatus, result: P.renderResult, insp: renderInspector, sa: P.renderSaMini, replay: P.renderReplay };
  for (const id of ids) $('#' + id).innerHTML = f[id](state);
};

function renderJourney(active) {
  const t = P.currentTx(state); const ol = $('#journey');
  if (!t) { ol.innerHTML = ''; return; }
  ol.innerHTML = t.frames.map((f, i) => `<li class="${i === active ? 'on' : ''} ${i === t.frames.length - 1 && active >= i ? (t.accepted ? 'ok' : 'bad') : ''}"><span class="num">${i + 1}</span><span class="nm">${esc(NODE_LABEL[f.node])}</span><span class="tx">${esc(f.text)}</span><span class="tt">${esc(f.proto)}</span><span class="tt">TTL ${f.ttl}</span></li>`).join('');
}
function onFrame(i, f) {
  const t = P.currentTx(state);
  $('#caption').innerHTML = `${icon('info', 16)}<span>${esc(f.text)}</span>`;
  renderJourney(i);
  void t;
}

// ---------- actions ----------
async function send(cfgOverride) {
  if (state.busy) return;
  const cfg = cfgOverride ?? state.cfg;
  state.busy = true; $('#btn-send').disabled = true;
  try {
    const run = await state.sim.run(cfg);
    state.run = run; state.txIndex = 0; state.attackerSub = 'captured';
    run.log.forEach((e) => state.logAll.push(e));
    state.logAll.push({ sep: true, text: `Packet #${String(run.packetNo).padStart(4, '0')} · ${run.cfg.protection === 'NONE' ? 'No IPsec' : PROTECTION_LABEL[run.cfg.protection] + ' ' + run.cfg.mode} · ${ATTACK_LABEL[run.cfg.attack]}` });
    const t = run.primary;
    state.history.push({ no: run.packetNo, protocol: run.cfg.protection === 'NONE' ? 'No IPsec' : PROTECTION_LABEL[run.cfg.protection], mode: run.secured ? run.cfg.mode : '—', attack: ATTACK_LABEL[run.cfg.attack], size: t.sent.length, overhead: run.overhead, dropped: t.dropped?.label ?? '—', accepted: t.accepted });
    if (run.establishment) { state.estView = run.establishment; state.estShown = 99; }
    renderAll();
    topo.draw(run.cfg);
    for (let i = 0; i < run.transmissions.length; i++) {
      state.txIndex = i;
      if (i > 0) { renderSome('status', 'result', 'insp'); $('#caption').innerHTML = `${icon('repeat', 16)}<span>Attacker replays the captured packet</span>`; }
      renderJourney(-1);
      await topo.play(run.transmissions[i], state.speed);
    }
    state.txIndex = run.transmissions.length - 1;
    renderSome('status', 'result', 'insp', 'sa', 'replay');
    const t0 = run.transmissions.at(-1);
    $('#caption').innerHTML = `${icon(t0.accepted ? 'check' : 'x', 16)}<span>${t0.accepted ? 'Packet accepted by Host B' : esc(`Dropped at ${t0.dropped.label}: ${t0.dropped.reason}`)}</span>`;
    return run;
  } finally { state.busy = false; validate(); $('#demo').innerHTML = renderDemo(state); }
}

async function runEstablishment() {
  const c = state.cfg;
  if (c.protection === 'NONE') { alert_(`Select AH, ESP or AH + ESP first: there is nothing to establish without IPsec.`); return; }
  state.sim.rekey();
  const L = (level, text, node) => state.logAll.push({ n: state.logAll.length + 1, level, text, node });
  const rec = await state.sim.ensureSAs({ ...c }, L);
  state.estView = rec; state.estShown = 0; $('#est').innerHTML = P.renderEstablish(state);
  for (let i = 1; i <= rec.steps.length; i++) { await sleep(state.speed === 'instant' ? 0 : 350); state.estShown = i; $('#est').innerHTML = P.renderEstablish(state); }
  renderSome('sa', 'replay'); $('#log').innerHTML = P.renderLog(state);
}
const alert_ = (msg) => { state.logAll.push({ n: 0, level: 'warn', text: msg, node: null }); $('#log').innerHTML = P.renderLog(state); };

async function doMatrix() {
  state.matrix = { running: true, done: 0, total: MATRIX_CASES.length * MATRIX_ATTACKS.length };
  $('#mtx').innerHTML = P.renderMatrix(state);
  const strict = state.cfg.strictSelector;
  const rows = await runMatrix({ strictSelector: strict, onProgress: (d) => { state.matrix.done = d; if (d % 5 === 0) $('#mtx').innerHTML = P.renderMatrix(state); } });
  state.matrix = { rows, strict };
  $('#mtx').innerHTML = P.renderMatrix(state);
}

async function demoRun() {
  const s = DEMO_STEPS[state.demo.step]; const runs = [];
  state.cfg = { ...state.cfg, ...s.cfgs[0] }; syncConfig();
  for (const c of s.cfgs) {
    state.cfg = { ...state.cfg, ...c }; syncConfig();
    state.sim.reset();
    const r = await send({ ...state.cfg });
    if (r) runs.push(r);
  }
  state.demo.results = s.results(runs); $('#demo').innerHTML = renderDemo(state);
}

function resetAll() {
  state.sim.reset(); state.run = null; state.txIndex = 0; state.logAll = []; state.history = []; state.estView = null; state.matrix = null;
  topo.clear(); renderAll(); syncConfig(); $('#caption').innerHTML = `${icon('info', 16)}<span>Simulation reset. New keys will be generated on the next protected packet.</span>`;
}

// ---------- events ----------
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]'); if (!el || el.disabled) return;
  const a = el.dataset.action;
  const set = (patch) => { Object.assign(state.cfg, patch); syncConfig(); };
  switch (a) {
    case 'prot': set({ protection: el.dataset.protection }); break;
    case 'mode': set({ mode: el.dataset.mode }); break;
    case 'attack': set({ attack: el.dataset.attack }); break;
    case 'send': send(); break;
    case 'reset': resetAll(); break;
    case 'stage': state.stage = el.dataset.stage; renderSome('insp'); break;
    case 'view': state.view = el.dataset.view; renderSome('insp'); break;
    case 'sub': state.attackerSub = el.dataset.sub; renderSome('insp'); break;
    case 'tx': state.txIndex = +el.dataset.i; renderSome('status', 'result', 'insp', 'replay'); break;
    case 'clear-log': state.logAll = []; $('#log').innerHTML = P.renderLog(state); break;
    case 'rekey': state.sim.rekey(); state.estView = null; renderSome('sa', 'replay'); $('#est').innerHTML = P.renderEstablish(state); break;
    case 'establish': runEstablishment(); break;
    case 'matrix': doMatrix(); break;
    case 'demo-open': state.demo.open = true; renderAll(); $('#demo').scrollIntoView({ block: 'nearest' }); break;
    case 'demo-close': state.demo.open = false; renderAll(); break;
    case 'demo-next': state.demo.step = Math.min(DEMO_STEPS.length - 1, state.demo.step + 1); state.demo.results = []; $('#demo').innerHTML = renderDemo(state); break;
    case 'demo-prev': state.demo.step = Math.max(0, state.demo.step - 1); state.demo.results = []; $('#demo').innerHTML = renderDemo(state); break;
    case 'demo-run': demoRun(); break;
    default: break;
  }
});
document.addEventListener('change', (e) => {
  if (e.target.dataset.action === 'reveal') { state.revealKeys = e.target.checked; $('#est').innerHTML = P.renderEstablish(state); }
  if (e.target.id === 'strict') { state.cfg.strictSelector = e.target.checked; }
  if (e.target.id === 'speed') state.speed = e.target.value;
});
document.addEventListener('input', (e) => {
  if (['srcIp', 'dstIp', 'payload', 'spoofIp'].includes(e.target.id)) {
    state.cfg[e.target.id] = e.target.value;
    $('#plen').textContent = `${new TextEncoder().encode(state.cfg.payload).length} / ${MAX_PAYLOAD} bytes`;
    validate();
    if (state.valid && !state.busy) { topo.draw(state.cfg); }
  }
});

buildConfig();
renderAll();
window.__sim = { state, send };
