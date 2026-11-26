const te = new TextEncoder();
const td = new TextDecoder();

function b64encode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importAesKey(secret) {
  const hash = await crypto.subtle.digest('SHA-256', te.encode(secret));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/** Encrypt UTF-8 text with AES-GCM; returns base64(iv || ciphertext). */
export async function encryptText(secret, plaintext) {
  if (!secret) throw new Error('Missing encryption key');
  const key = await importAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plaintext));
  const packed = new Uint8Array(iv.length + ct.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(ct), iv.length);
  return b64encode(packed);
}

export async function decryptText(secret, packedB64) {
  if (!secret) throw new Error('Missing encryption key');
  const key = await importAesKey(secret);
  const packed = b64decode(packedB64);
  const iv = packed.slice(0, 12);
  const ct = packed.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return td.decode(pt);
}

export function randomToken(bytes = 32) {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomOtp6() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
  return String(n).padStart(6, '0');
}

export async function sha256Hex(value) {
  const dig = await crypto.subtle.digest('SHA-256', te.encode(value));
  return [...new Uint8Array(dig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
