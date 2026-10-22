# Architecture

## Layers
`src/engine/` is pure JavaScript with no DOM access, so the same code runs in the browser and in the Node test suite. `src/ui/` renders whatever the engine returns; it never decides a protocol outcome.

| Module | Role |
|---|---|
| `crypto.js` | HMAC-SHA-256 (truncated to 128 bits), AES-128-CBC, ECDH P-256, HKDF-SHA-256 (WebCrypto / node:crypto) |
| `ipv4.js` | 20-byte IPv4 header build/parse, RFC 1071 checksum, router TTL decrement, AH mutable-field zeroing |
| `sa.js` | Security Association (SPI, keys, sequence counter) and the SA database |
| `replay.js` | 32-packet sliding anti-replay window |
| `ipsec.js` | `protect()` on the sender; `processInbound()` on the receiver (parses bytes, never trusts the UI) |
| `establish.js` | Simplified SA establishment (educational, not IKEv2) |
| `attacker.js` | Sniff, tamper, forge, replay, modify-source-IP |
| `dissect.js` | Turns real bytes into labelled layers for the inspector |
| `simulator.js` | Orchestrates one packet through the topology with per-hop TTL |
| `matrix.js` | Runs all 35 protection × mode × attack cases |

## Topology
Transport mode: Host A → Untrusted Internet (3 router hops) → Host B (verifier). Tunnel mode: Host A → Gateway A → Internet → Gateway B (verifier) → Host B. Gateways use RFC 5737 documentation addresses 203.0.113.1 and 198.51.100.1.

## Packet formats built
* Transport AH: `IP | AH(12 B + 16 B ICV) | payload` (+28 B)
* Transport ESP: `IP | ESP hdr(8) | IV(16) | ciphertext | ICV(16)`
* Tunnel: a new outer IPv4 header (+20 B) wraps the whole original packet before AH/ESP processing.
* AH+ESP: ESP first, then AH over the result. Two separate SAs.

Measured overhead for the 34-byte sample message: AH transport +28 B, AH tunnel +48, ESP transport +54, ESP tunnel +70, AH+ESP transport +82, AH+ESP tunnel +98.

## Receiver pipeline
Parse IPv4 and validate checksum → read protocol field (50/51) → SA lookup by SPI + protocol → anti-replay *check* (no state change) → ICV verification (constant-time) → anti-replay *update* → decrypt → decapsulate → policy check → optional strict selector check → deliver. A packet is dropped at the node that performs the failing step (Host B in transport mode, Gateway B in tunnel mode).

## Changes from the prototype
* Separate AH and ESP SAs with their own SPIs, keys, sequence counters and replay windows.
* Receiver parses the wire bytes; protocol and mode are never read from the UI.
* "Application Payload" replaces the prototype's fake TCP header (IP protocol 253).
* IPv4 checksum is computed and validated; AH zeroes mutable fields (TOS, flags, fragment offset, TTL, checksum).
* TTL decremented per router hop; drops are attributed to the real verifying node.
* Anti-replay window of 32; authentication is verified before the window moves.
* Added Modify-source-IP attack, a No-IPsec baseline, a simplified SA establishment, a data-driven comparison table and a 35-case verification matrix.
* HMAC-SHA-256-128 and AES-128-CBC retained from the prototype (sound for teaching).
