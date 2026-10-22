// Comparison table (No IPsec / AH / ESP / AH + ESP). The claims are written once, here, and
// tests/capabilities.test.js checks every one of them against the real simulator behaviour.

export const COLUMNS = Object.freeze(['NONE', 'AH', 'ESP', 'AH_ESP']);

const yes = (text = 'Yes') => ({ v: 'yes', text });
const no = (text = 'No') => ({ v: 'no', text });
const part = (text) => ({ v: 'partial', text });

export const CAPABILITIES = Object.freeze([
  {
    key: 'authentication',
    feature: 'Authentication (data origin)',
    NONE: no(), AH: yes(), ESP: yes('Yes (ICV)'), AH_ESP: yes(),
  },
  {
    key: 'integrity',
    feature: 'Integrity',
    NONE: no(), AH: yes(), ESP: yes('Yes (ICV)'), AH_ESP: yes(),
  },
  {
    key: 'confidentiality',
    feature: 'Confidentiality',
    NONE: no(), AH: no(), ESP: yes(), AH_ESP: yes(),
  },
  {
    key: 'encryption',
    feature: 'Encryption',
    NONE: no(), AH: no(), ESP: yes('AES-128-CBC'), AH_ESP: yes('AES-128-CBC'),
  },
  {
    key: 'antiReplay',
    feature: 'Anti-replay',
    NONE: no(), AH: yes('Yes (sequence + window)'), ESP: yes('Yes (sequence + window)'), AH_ESP: yes(),
  },
  {
    key: 'payload',
    feature: 'Protected payload',
    NONE: no('None'), AH: part('Authenticated, readable'), ESP: yes('Encrypted + authenticated'), AH_ESP: yes('Encrypted + authenticated'),
  },
  {
    key: 'header',
    feature: 'Protected IP header',
    NONE: no('None'),
    AH: part('Immutable fields authenticated'),
    ESP: no('Not covered (tunnel: inner header is)'),
    AH_ESP: part('Outer immutable fields (AH)'),
  },
]);

export const CAPABILITY_NOTES = Object.freeze([
  'ESP is always used with an ICV in this simulator (ESP without authentication is not offered).',
  'AH authenticates the IP header except its mutable fields (TOS, flags, fragment offset, TTL, checksum), which are zeroed before the ICV is computed.',
  'In tunnel mode ESP protects the original IP header (encrypted and authenticated) but not the new outer header.',
]);
