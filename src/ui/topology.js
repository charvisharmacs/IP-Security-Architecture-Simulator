// Network topology (SVG) and packet animation. The animation plays the frames produced by the
// simulator: where the packet is, what happens there, its TTL and whether it was dropped.

import { esc, iconPaths, sleep } from './dom.js';
import { GATEWAY_A_IP, GATEWAY_B_IP, INTERNET_HOPS, NODE_LABEL } from '../engine/simulator.js';

const LINE_Y = 120;
const POS_TRANSPORT = { hostA: 150, internet: 480, hostB: 810 };
const POS_TUNNEL = { hostA: 100, gwA: 290, internet: 480, gwB: 670, hostB: 860 };
const ICON = { hostA: 'host', hostB: 'host', gwA: 'router', gwB: 'router', internet: 'globe' };

const nodeSub = (id, cfg) =>
  ({ hostA: cfg.srcIp, hostB: cfg.dstIp, gwA: GATEWAY_A_IP, gwB: GATEWAY_B_IP, internet: `${INTERNET_HOPS} router hops` }[id]);

const svgIcon = (name, x, y, size) =>
  `<svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${iconPaths(name)}</svg>`;

export function routeFor(cfg) {
  return cfg.protection !== 'NONE' && cfg.mode === 'tunnel'
    ? ['hostA', 'gwA', 'internet', 'gwB', 'hostB']
    : ['hostA', 'internet', 'hostB'];
}

export function drawTopology(el, cfg) {
  const tunnel = cfg.protection !== 'NONE' && cfg.mode === 'tunnel';
  const route = routeFor(cfg);
  const pos = tunnel ? POS_TUNNEL : POS_TRANSPORT;
  const secured = cfg.protection !== 'NONE';
  const bandClass = cfg.protection === 'AH' ? 'ah' : cfg.protection === 'ESP' ? 'esp' : 'both';
  const protoText = { AH: 'AH (protocol 51)', ESP: 'ESP (protocol 50)', AH_ESP: 'AH + ESP' }[cfg.protection];

  let band = '';
  if (secured) {
    const a = tunnel ? pos.gwA : pos.hostA;
    const b = tunnel ? pos.gwB : pos.hostB;
    band = `<rect class="tunnel-band ${bandClass}" x="${a - 70}" y="54" width="${b - a + 140}" height="146" rx="18"/>
      <text class="band-label ${bandClass}" x="${(a + b) / 2}" y="46">${tunnel ? 'IPSEC TUNNEL' : 'IPSEC END-TO-END (TRANSPORT MODE)'} · ${esc(protoText)}</text>`;
  } else {
    band = `<text class="band-label none" x="480" y="46">NO IPSEC · TRAFFIC CROSSES THE NETWORK UNPROTECTED</text>`;
  }

  const links = route.slice(0, -1).map((id, i) => {
    const next = route[i + 1];
    const w = (n) => (n === 'internet' ? 75 : 48);
    return `<line class="link" data-link="${id}-${next}" x1="${pos[id] + w(id)}" y1="${LINE_Y}" x2="${pos[next] - w(next)}" y2="${LINE_Y}"/>`;
  }).join('');

  const nodes = route.map((id) => {
    const w = id === 'internet' ? 150 : 96;
    const x = pos[id];
    return `<g class="tnode ${id === 'internet' ? 'inet' : ''}" data-node="${id}">
      <rect class="box" x="${x - w / 2}" y="70" width="${w}" height="80" rx="12"/>
      ${svgIcon(ICON[id], x - 14, 80, 28)}
      <text class="t-label" x="${x}" y="170">${esc(NODE_LABEL[id])}</text>
      <text class="t-sub" x="${x}" y="186">${esc(nodeSub(id, cfg))}</text>
    </g>`;
  }).join('');

  const ix = pos.internet;
  const attacker = `<g class="mal" id="mal">
    <line class="mal-link" x1="${ix}" y1="192" x2="${ix}" y2="208"/>
    <rect class="box" x="${ix - 84}" y="208" width="168" height="38" rx="10"/>
    ${svgIcon('eye', ix - 72, 217, 20)}
    <text x="${ix + 8}" y="224" class="t-label" style="font-size:12px">Mallory</text>
    <text x="${ix + 8}" y="238" class="t-sub" style="font-size:10px">attacker on the path</text>
  </g>`;

  el.innerHTML = `<svg class="topo" viewBox="0 0 960 252" role="img" aria-label="Network topology: ${route.map((r) => NODE_LABEL[r]).join(' to ')}">
    ${band}${links}${nodes}${attacker}
    <g class="marker hidden" id="marker" style="transform:translate(${pos.hostA}px, ${LINE_Y}px)"><rect x="-56" y="-12" width="112" height="24" rx="7"/><text y="4" id="marker-t">IP</text></g>
  </svg>`;
  return { pos, route };
}

export function createTopology(container, onFrame) {
  let layout = null;
  let token = 0;

  const q = (sel) => container.querySelector(sel);
  const nodeEl = (id) => container.querySelector(`[data-node="${id}"]`);

  function draw(cfg) {
    token++; // cancels a running animation
    layout = drawTopology(container, cfg);
  }

  function clearStates() {
    container.querySelectorAll('.tnode').forEach((n) => n.setAttribute('class', `tnode ${n.dataset.node === 'internet' ? 'inet' : ''}`));
    container.querySelectorAll('.link').forEach((n) => n.setAttribute('class', 'link'));
    container.querySelectorAll('.badge-mark').forEach((n) => n.remove());
    q('#mal')?.setAttribute('class', 'mal');
  }

  function place(marker, x, animate) {
    if (!animate) {
      marker.style.transition = 'none';
      marker.style.transform = `translate(${x}px, ${LINE_Y}px)`;
      void marker.getBoundingClientRect();
      marker.style.transition = '';
    } else {
      marker.style.transform = `translate(${x}px, ${LINE_Y}px)`;
    }
  }

  function addBadge(id, ok) {
    const node = nodeEl(id);
    if (!node) return;
    const box = node.querySelector('.box');
    const x = +box.getAttribute('x') + +box.getAttribute('width') - 4;
    node.insertAdjacentHTML('beforeend', `<g class="badge-mark ${ok ? 'ok' : ''}" transform="translate(${x} 74)"><circle r="10"/><path d="${ok ? 'M-4 0l3 3 5-6' : 'M-4 -4l8 8M4 -4l-8 8'}"/></g>`);
  }

  /** Play every frame of a transmission. Resolves when finished (or cancelled by draw()/another play()). */
  async function play(transmission, speed = 'normal') {
    if (!layout) return;
    const my = ++token;
    const frames = transmission.frames;
    const move = speed === 'instant' ? 0 : speed === 'fast' ? 280 : 760;
    const rest = speed === 'instant' ? 0 : speed === 'fast' ? 240 : 700;
    const marker = q('#marker');
    const mt = q('#marker-t');
    clearStates();
    marker.classList.remove('hidden');
    const { pos, route } = layout;
    let lastIdx = -1;

    for (let i = 0; i < frames.length; i++) {
      if (my !== token) return;
      const f = frames[i];
      const x = pos[f.node];
      if (x === undefined) continue;
      const first = i === 0;
      const sameNode = lastIdx >= 0 && frames[lastIdx].node === f.node;
      place(marker, x, !first && move > 0);
      marker.setAttribute('class', `marker ${f.state === 'bad' ? 'bad' : f.state === 'ok' ? 'ok' : f.proto === 'AH' ? 'ah' : f.proto === 'ESP' ? 'esp' : ''}`);
      mt.textContent = `${f.proto} · TTL ${f.ttl}`;
      container.querySelectorAll('.tnode.active').forEach((n) => n.classList.remove('active'));
      nodeEl(f.node)?.classList.add('active');
      if (f.node === 'internet') q('#mal')?.classList.add('hit');
      onFrame?.(i, f);
      if (!sameNode) await sleep(move);
      else await sleep(0);
      await sleep(rest);
      lastIdx = i;
    }
    if (my !== token) return;

    // final state: ring + badge on the last node, everything beyond it dimmed
    const last = frames[frames.length - 1];
    container.querySelectorAll('.tnode.active').forEach((n) => n.classList.remove('active'));
    const lastNode = nodeEl(last.node);
    const ok = transmission.accepted;
    const endNode = transmission.droppedNode ?? 'hostB';
    nodeEl(endNode)?.classList.add(ok ? 'ok' : 'bad');
    addBadge(endNode, ok);
    const endIdx = route.indexOf(endNode);
    route.forEach((id, i) => {
      if (i > endIdx) nodeEl(id)?.classList.add('dim');
      if (i >= endIdx && i < route.length - 1) container.querySelector(`[data-link="${id}-${route[i + 1]}"]`)?.classList.add('dim');
    });
    marker.setAttribute('class', `marker ${ok ? 'ok' : 'bad'}`);
    if (!ok) place(marker, pos[endNode], false);
    void lastNode;
  }

  return { draw, play, clear: () => { token++; clearStates(); q('#marker')?.classList.add('hidden'); } };
}
