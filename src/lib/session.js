import { randomToken } from './crypto-util.js';
import { isAdminEmail, normalizeEmail } from './email.js';
import { getAllowlistEntry, getUser } from './db.js';

const PARTIAL_COOKIE = 'olt_partial';
const SESSION_COOKIE = 'olt_sid';
const PARTIAL_TTL_SEC = 15 * 60;
const SESSION_TTL_SEC = 60 * 60 * 24 * 14; // 14 days

function cookieAttrs(maxAge) {
  return `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function setPartialCookie(token) {
  return `${PARTIAL_COOKIE}=${encodeURIComponent(token)}; ${cookieAttrs(PARTIAL_TTL_SEC)}`;
}

export function setSessionCookie(token) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; ${cookieAttrs(SESSION_TTL_SEC)}`;
}

export function clearAuthCookies() {
  return [
    `${PARTIAL_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  ];
}

export async function createPartialSession(env, email) {
  const token = randomToken(24);
  const payload = {
    type: 'partial',
    email: normalizeEmail(email),
    exp: Date.now() + PARTIAL_TTL_SEC * 1000,
  };
  await env.AUTH_KV.put(`partial:${token}`, JSON.stringify(payload), {
    expirationTtl: PARTIAL_TTL_SEC,
  });
  return token;
}

export async function readPartialSession(env, request) {
  const cookies = parseCookies(request);
  const token = cookies[PARTIAL_COOKIE];
  if (!token) return null;
  const raw = await env.AUTH_KV.get(`partial:${token}`);
  if (!raw) return null;
  const data = JSON.parse(raw);
  if (data.exp < Date.now()) {
    await env.AUTH_KV.delete(`partial:${token}`);
    return null;
  }
  return { ...data, token };
}

export async function destroyPartialSession(env, request) {
  const cookies = parseCookies(request);
  const token = cookies[PARTIAL_COOKIE];
  if (token) await env.AUTH_KV.delete(`partial:${token}`);
}

export async function createFullSession(env, email, role) {
  const token = randomToken(32);
  const payload = {
    type: 'full',
    email: normalizeEmail(email),
    role,
    totpOk: true,
    exp: Date.now() + SESSION_TTL_SEC * 1000,
  };
  await env.AUTH_KV.put(`session:${token}`, JSON.stringify(payload), {
    expirationTtl: SESSION_TTL_SEC,
  });
  return token;
}

export async function readFullSession(env, request) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const raw = await env.AUTH_KV.get(`session:${token}`);
  if (!raw) return null;
  const data = JSON.parse(raw);
  if (!data.totpOk || data.exp < Date.now()) {
    await env.AUTH_KV.delete(`session:${token}`);
    return null;
  }
  // Re-check allowlist on every request so revokes take effect
  const entry = await getAllowlistEntry(env.DB, data.email);
  if (!entry) {
    await env.AUTH_KV.delete(`session:${token}`);
    return null;
  }
  const user = await getUser(env.DB, data.email);
  if (!user || !user.totp_confirmed) {
    await env.AUTH_KV.delete(`session:${token}`);
    return null;
  }
  return {
    email: normalizeEmail(data.email),
    role: entry.role || (isAdminEmail(data.email) ? 'admin' : 'member'),
    totpOk: true,
    token,
  };
}

export async function destroyFullSession(env, request) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (token) await env.AUTH_KV.delete(`session:${token}`);
}

export async function rateLimit(env, key, limit, windowSec) {
  const kvKey = `rl:${key}`;
  const raw = await env.AUTH_KV.get(kvKey);
  const now = Date.now();
  let state = raw ? JSON.parse(raw) : { count: 0, reset: now + windowSec * 1000 };
  if (now > state.reset) state = { count: 0, reset: now + windowSec * 1000 };
  state.count += 1;
  const ttl = Math.max(1, Math.ceil((state.reset - now) / 1000));
  await env.AUTH_KV.put(kvKey, JSON.stringify(state), { expirationTtl: ttl });
  return state.count <= limit;
}
