# Methodology and algorithms

## Sender (`protect`)
1. Build the plain IPv4 packet (protocol 253, application payload).
2. Tunnel mode: Gateway A decrements the inner TTL, then prepends a new outer header.
3. ESP: pad plaintext to the AES block size, append pad-length and next-header, encrypt with AES-128-CBC and a fresh random IV, compute ICV = HMAC-SHA-256(key, ESP header ‖ IV ‖ ciphertext) truncated to 16 bytes (encrypt-then-MAC).
4. AH: copy the packet with mutable fields (TOS, flags, fragment offset, TTL, checksum) and the ICV field set to zero, compute the ICV over it, insert the AH header.
5. Increment the per-SA sequence counter; fix the outer IPv4 length, protocol and checksum.

## Receiver (`processInbound`)
Parse and checksum-validate the header, select AH/ESP by protocol number, look up the SA by SPI, check the replay window, verify the ICV in constant time, update the window only on success, decrypt, remove padding, decapsulate, apply policy, deliver.

## Anti-replay
Window of 32. A sequence number is rejected if it is zero, older than `highest − 31`, or already seen. On success the bitmap is advanced.

## Simplified SA establishment (educational model, not IKEv2)
Initiator proposes parameters → responder accepts → ephemeral ECDH P-256 → both sides authenticate the transcript with a pre-shared key (HMAC) → HKDF-SHA-256 derives AH-auth, ESP-auth and ESP-enc keys → SPIs are assigned → SAs installed. A wrong PSK makes establishment fail.

## Attack model
Sniff: copy bytes, test whether the payload is readable. Tamper: flip a byte. Forge: build a packet with random keys and the observed SPI/sequence. Replay: resend a captured packet. Modify source IP: rewrite the outer source and recompute the IP checksum. Outcome is classified defended / succeeded / accepted-no-effect by comparing what Host B delivered with what Host A sent.

## Key finding
ESP does not authenticate the outer IP header, so a source-address change is accepted in ESP transport mode, has no effect in ESP tunnel mode (the authenticated inner packet is intact), and is always rejected by AH. The optional strict selector check makes ESP reject it too.
