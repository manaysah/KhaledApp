/** Minimal RFC 6238 TOTP (SHA-1, 30s, 6 digits) using Web Crypto. */

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(bytes = 20) {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return base32Encode(buf);
}

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(secret) {
  const cleaned = secret.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function counterBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // big-endian uint64; JS safe for TOTP counters
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  return new Uint8Array(buf);
}

async function hotp(secretBytes, counter) {
  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(counter)));
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

export async function generateTotp(secretBase32, atMs = Date.now(), step = 30) {
  const counter = Math.floor(atMs / 1000 / step);
  return hotp(base32Decode(secretBase32), counter);
}

/** Verify with ±1 window. */
export async function verifyTotp(secretBase32, code, atMs = Date.now(), step = 30, window = 1) {
  const cleaned = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleaned)) return false;
  const counter = Math.floor(atMs / 1000 / step);
  const secret = base32Decode(secretBase32);
  for (let w = -window; w <= window; w++) {
    const expected = await hotp(secret, counter + w);
    if (expected === cleaned) return true;
  }
  return false;
}

export function otpauthUri({ secret, email, issuer = 'Our Little Tide' }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
