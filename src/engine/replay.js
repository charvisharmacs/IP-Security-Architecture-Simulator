// Anti-replay sliding window (RFC 4303 section 3.4.3 / RFC 4302 section 3.4.3).
// The window covers sequence numbers (highest - size, highest]. Anything at or below the left edge is
// "too old", anything inside the window that was already accepted is a duplicate.
//
// check()  never changes state.
// update() must only be called AFTER the packet's ICV has been verified (an unauthenticated
//          sequence number must never move the window).

export const DEFAULT_WINDOW = 32;

export class ReplayWindow {
  constructor(size = DEFAULT_WINDOW) {
    this.size = size;
    this.reset();
  }

  reset() {
    this.highest = 0;
    this.seen = new Set();
  }

  check(seq) {
    if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) {
      return { ok: false, kind: 'invalid', reason: `Sequence number ${seq} is outside the 32-bit range` };
    }
    if (seq === 0) {
      return { ok: false, kind: 'zero', reason: 'Sequence number 0 is never sent by a conforming sender' };
    }
    if (seq > this.highest) {
      return { ok: true, kind: 'new', reason: `New highest sequence number (previous highest ${this.highest})` };
    }
    if (seq <= this.highest - this.size) {
      return {
        ok: false,
        kind: 'too-old',
        reason: `REPLAY DETECTED: sequence ${seq} is older than the ${this.size}-packet window (left edge ${this.highest - this.size + 1})`,
      };
    }
    if (this.seen.has(seq)) {
      return { ok: false, kind: 'duplicate', reason: `REPLAY DETECTED: sequence ${seq} was already accepted` };
    }
    return { ok: true, kind: 'in-window', reason: `Sequence ${seq} is inside the window and has not been seen` };
  }

  update(seq) {
    if (seq > this.highest) {
      this.highest = seq;
      for (const s of this.seen) if (s <= this.highest - this.size) this.seen.delete(s);
    }
    this.seen.add(seq);
  }

  /** Data for the UI: every position in the window with its state. */
  snapshot() {
    const cells = [];
    const lo = Math.max(1, this.highest - this.size + 1);
    for (let s = lo; s <= Math.max(this.highest, lo); s++) {
      if (this.highest === 0) break;
      cells.push({ seq: s, accepted: this.seen.has(s) });
    }
    return { highest: this.highest, size: this.size, left: lo, cells };
  }
}
