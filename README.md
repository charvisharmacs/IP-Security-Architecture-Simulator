# IP Security Architecture Simulator

An interactive, byte-level educational simulator for **IPsec (Internet Protocol Security)** architecture. The simulator models the Authentication Header (AH), Encapsulating Security Payload (ESP), Security Associations (SAs), and a 32-packet anti-replay sliding window, demonstrating how network-layer cryptographic protocols defend against sniffing, tampering, forgery, replay, and IP spoofing attacks.

Unlike static diagrams or mock tools, this project executes real cryptographic primitives (HMAC-SHA-256-128, AES-128-CBC, HKDF) directly on real IPv4 packet bytes in both Node.js and the browser.

---

## Simulation Workflow & Architecture

The simulator models network-layer IPsec packet processing across multiple stages:
- **Topology Animation**: Visualizes packet transit across simulated nodes (Host A, intermediate routers with Mallory, and Host B / security gateways) with hop-by-hop TTL decrementing.
- **Byte-Level Packet Inspector**: Inspects raw packets at four discrete boundaries: *Before IPsec*, *After IPsec*, *At Attacker*, and *At Receiver*, complete with field-by-field dissection and byte hex representations.
- **Anti-Replay Window**: Models the 32-packet bitmap sliding window to catch duplicate and out-of-order packets.
- **Verification Matrix**: Comprehensive automated test verification across 35 protocol, mode, and attack scenarios.

---

## Key Features

- **Protocols Supported**:
  - **No IPsec** (Baseline demonstration of unprotected cleartext IPv4 traffic)
  - **AH (Authentication Header)**: Data integrity and origin authentication covering payload and immutable IPv4 header fields.
  - **ESP (Encapsulating Security Payload)**: Confidentiality (AES-128-CBC) and integrity (HMAC-SHA-256-128) covering payload and ESP headers.
  - **AH + ESP Bundle**: Layered authentication and encryption.
- **Modes of Operation**:
  - **Transport Mode**: End-to-end host-to-host protection (3-node route: Host A → Internet → Host B).
  - **Tunnel Mode**: Gateway-to-gateway encapsulation with new outer IPv4 headers (5-node route: Host A → Gateway A → Internet → Gateway B → Host B).
- **Adversary & Attack Toolkit**:
  - **Sniff**: Inspects packet exposure across routers.
  - **Tamper**: Flips individual payload or header bits in transit to verify integrity checks.
  - **Forge**: Injects packets using observed SPI/sequence numbers with untrusted keys.
  - **Replay**: Resends legitimate captured packets to test the anti-replay bitmap.
  - **Modify Source IP**: Demonstrates header mutability and the contrast between AH (which detects outer IP alterations) and ESP (which does not protect outer headers).
- **Security Associations (SAs) & Anti-Replay**:
  - Independent inbound and outbound SAs for AH and ESP with SPI indexing and sequence tracking.
  - 32-packet sliding replay window with bitmap verification and in-order / out-of-order evaluation.
  - Educational ephemeral ECDH + PSK + HKDF key establishment model.
- **Verification Matrix**:
  - Built-in verification matrix verifying all 35 combinations of protocols, modes, and attacks.

---

## Architecture & Directory Guide

The codebase strictly decouples the protocol engine from the presentation layer. The engine has **zero DOM dependencies** and runs identically in Node.js test runners and client-side browsers.

```
IP-Security-Architecture-Simulator/
├── src/
│   ├── engine/                # Core protocol engine (Pure JS, zero DOM)
│   │   ├── crypto.js          # WebCrypto / Node crypto abstractions (HMAC, AES, ECDH, HKDF)
│   │   ├── ipv4.js            # IPv4 header builder, parser, and RFC 1071 checksum
│   │   ├── ipsec.js           # AH/ESP encapsulation, mutable zeroing, ICV verification
│   │   ├── sa.js              # Security Association database and lookup
│   │   ├── replay.js          # 32-packet anti-replay sliding window bitmap
│   │   ├── attacker.js        # Attacker toolkit (tamper, forge, replay, spoof)
│   │   ├── simulator.js       # End-to-end multi-hop network orchestrator
│   │   └── dissect.js         # Byte-level layer breakdown for the inspector
│   ├── ui/                    # Presentation and interaction components
│   │   ├── topology.js        # SVG network topology animation
│   │   ├── inspector.js       # Multi-stage packet field and hex view
│   │   ├── panels.js          # SA tables, replay status, and event log
│   │   └── demo.js            # Interactive guided walk-through script
│   ├── styles/                # Clean design system styles
│   └── main.js                # Application entry point
├── tests/                     # Automated test suite (95 tests)
│   ├── crypto.test.js         # NIST / RFC reference vector tests
│   ├── ipv4.test.js           # IPv4 parsing, checksum, and routing tests
│   ├── ipsec.test.js          # AH/ESP processing and byte-level attack defense
│   ├── replay-bytes.test.js   # Sliding window edge cases and duplicate checks
│   └── simulator.test.js      # Full simulation scenarios and matrix verification
├── docs/                      # Technical documentation and specifications
│   ├── architecture.md        # Protocol engine architecture & topology
│   ├── methodology.md         # Encapsulation, decapsulation, & algorithms
│   └── references.md          # RFC and cryptographic standards references
└── index.html                 # Web dashboard markup
```

---

## Technologies Used

- **Language & Runtime**: Modern JavaScript (ES Modules), Node.js (v20+)
- **Cryptographic Primitives**: Web Crypto API (`crypto.subtle`) in the browser, `node:crypto` in Node.js
- **Build Tool**: Vite with `vite-plugin-singlefile` (compiles to a portable, standalone HTML file that runs from disk without a backend server)
- **Testing**: Node.js built-in test runner (`node --test`)
- **Graphics & Styling**: SVG topology animations and Vanilla CSS (no heavy CSS framework overhead)

---

## Getting Started

### Prerequisites
- Node.js (version 20.x or later recommended)
- npm

### Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/charvisharmacs/IP-Security-Architecture-Simulator.git
cd IP-Security-Architecture-Simulator
npm install
```

### Development Server
Start the local development server:
```bash
npm run dev
```
Open your browser at `http://127.0.0.1:5173`.

### Running Tests
Execute the automated test suite:
```bash
npm test
```

### Production Build
Build the self-contained single-file HTML bundle:
```bash
npm run build
```
The compiled output is saved to `dist/index.html`. It can be opened directly in any modern web browser without a web server.

---

## Test Verification

The engine is covered by **95 automated tests** validating behavior and conformance against published cryptographic and networking test vectors:
- **NIST FIPS 180-4**: SHA-256 reference vector (`"abc"`)
- **RFC 4231**: HMAC-SHA-256 Test Cases 1 and 2
- **RFC 4868**: HMAC-SHA-256 truncation to 128-bit ICV
- **NIST FIPS 197 & SP 800-38A (F.2.1)**: AES-128-CBC encryption and decryption
- **RFC 5869**: HKDF-SHA-256 Test Case 1
- **RFC 1071**: Internet Checksum verification
- **Replay Window**: In-order, out-of-order, boundary duplicates, and sliding-window pruning
- **Attack Defenses**: Verification of drops at receiving nodes for tampered, forged, and replayed packets

```
ℹ tests 95
ℹ suites 0
ℹ pass 95
ℹ fail 0
```

---

## Current Scope & Limitations

This project is created for educational study and protocol analysis:
- **IPv4 Only**: Uses standard 20-byte IPv4 headers. IPv6, IP options, and IP packet fragmentation are not implemented.
- **Educational SA Establishment**: Uses an ephemeral ECDH + PSK + HKDF exchange model to demonstrate key derivation; it is not a full IKEv2 implementation.
- **Fixed Anti-Replay Window**: Implements a 32-packet sliding window; Extended Sequence Numbers (64-bit ESN) are not supported.
- **No Live Traffic Interception**: Simulates discrete packets across simulated virtual nodes; not designed as a host network driver or VPN client.
