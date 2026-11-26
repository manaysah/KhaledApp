import { sendLoginCode, normalizeEmail, isValidEmail } from '../lib/email.js';
import {
  getAllowlistEntry,
  getUser,
  upsertUserPendingTotp,
  confirmUserTotp,
} from '../lib/db.js';
import {
  createPartialSession,
  setPartialCookie,
  clearAuthCookies,
  rateLimit,
  readPartialSession,
  readFullSession,
  destroyPartialSession,
  destroyFullSession,
  createFullSession,
  setSessionCookie,
} from '../lib/session.js';
import { randomOtp6, sha256Hex, encryptText, decryptText } from '../lib/crypto-util.js';
import { generateTotpSecret, otpauthUri, verifyTotp } from '../lib/totp.js';
import { json, readJson, methodNotAllowed, withCookies } from '../lib/http.js';

const OTP_TTL_SEC = 10 * 60;

export async function handleAuth(request, env, pathname) {
  if (pathname === '/api/auth/request-otp') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return requestOtp(request, env);
  }
  if (pathname === '/api/auth/verify-otp') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return verifyOtp(request, env);
  }
  if (pathname === '/api/auth/totp/setup') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return totpSetup(request, env);
  }
  if (pathname === '/api/auth/totp/confirm') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return totpConfirm(request, env);
  }
  if (pathname === '/api/auth/totp/verify') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return totpVerify(request, env);
  }
  if (pathname === '/api/auth/me') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return me(request, env);
  }
  if (pathname === '/api/auth/logout') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return logout(request, env);
  }
  return json({ error: 'Not found' }, 404);
}

async function requestOtp(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body?.email);
  if (!isValidEmail(email)) {
    return json({ error: 'Enter a valid email address.' }, 400);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowedIp = await rateLimit(env, `otp-ip:${ip}`, 10, 60 * 60);
  const allowedEmail = await rateLimit(env, `otp-email:${email}`, 5, 60 * 60);
  if (!allowedIp || !allowedEmail) {
    return json({ error: 'Too many requests. Try again later.' }, 429);
  }

  const entry = await getAllowlistEntry(env.DB, email);
  if (!entry) {
    return json({ error: 'This email is not allowed to sign in.' }, 403);
  }

  const code = randomOtp6();
  const codeHash = await sha256Hex(`${email}:${code}`);
  await env.AUTH_KV.put(
    `otp:${email}`,
    JSON.stringify({ hash: codeHash, attempts: 0, exp: Date.now() + OTP_TTL_SEC * 1000 }),
    { expirationTtl: OTP_TTL_SEC },
  );

  const sent = await sendLoginCode(env, email, code);
  if (!sent.ok) {
    return json({ error: sent.error || 'Could not send login code.' }, 500);
  }

  const payload = {
    ok: true,
    email,
    message: 'If this email is allowed, a login code was sent.',
  };
  if (sent.mode === 'dev') {
    payload.devCode = code;
    payload.message = 'Dev mode: use the code below (email not sent).';
  }
  return json(payload);
}

async function verifyOtp(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body?.email);
  const code = String(body?.code || '').replace(/\s+/g, '');

  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return json({ error: 'Invalid email or code.' }, 400);
  }

  const okRl = await rateLimit(env, `verify-otp:${email}`, 20, 60 * 60);
  if (!okRl) return json({ error: 'Too many attempts. Try again later.' }, 429);

  const entry = await getAllowlistEntry(env.DB, email);
  if (!entry) {
    return json({ error: 'This email is not allowed to sign in.' }, 403);
  }

  const raw = await env.AUTH_KV.get(`otp:${email}`);
  if (!raw) return json({ error: 'Code expired or not found. Request a new one.' }, 400);

  const record = JSON.parse(raw);
  if (record.exp < Date.now()) {
    await env.AUTH_KV.delete(`otp:${email}`);
    return json({ error: 'Code expired. Request a new one.' }, 400);
  }
  if (record.attempts >= 5) {
    await env.AUTH_KV.delete(`otp:${email}`);
    return json({ error: 'Too many incorrect attempts. Request a new code.' }, 400);
  }

  const hash = await sha256Hex(`${email}:${code}`);
  if (hash !== record.hash) {
    record.attempts += 1;
    await env.AUTH_KV.put(`otp:${email}`, JSON.stringify(record), {
      expirationTtl: Math.max(1, Math.ceil((record.exp - Date.now()) / 1000)),
    });
    return json({ error: 'Incorrect code.' }, 401);
  }

  await env.AUTH_KV.delete(`otp:${email}`);

  const user = await getUser(env.DB, email);
  const needsTotpSetup = !user || !user.totp_confirmed || !user.totp_secret_enc;

  const partial = await createPartialSession(env, email);
  const cookies = [...clearAuthCookies(), setPartialCookie(partial)];

  return withCookies(
    json({
      ok: true,
      email,
      role: entry.role,
      needsTotpSetup,
      next: needsTotpSetup ? 'totp_setup' : 'totp_verify',
    }),
    cookies,
  );
}

async function totpSetup(request, env) {
  const full = await readFullSession(env, request);
  if (full) return json({ error: 'Already signed in.' }, 400);

  const partial = await readPartialSession(env, request);
  if (!partial) return json({ error: 'Email verification required first.' }, 401);

  const existing = await getUser(env.DB, partial.email);
  if (existing?.totp_confirmed && existing.totp_secret_enc) {
    return json({ error: 'Authenticator already enrolled. Enter your code to continue.' }, 400);
  }

  const secret = generateTotpSecret();
  const encKey = env.TOTP_ENCRYPTION_KEY || env.SESSION_SECRET;
  if (!encKey) {
    return json({ error: 'Server missing TOTP_ENCRYPTION_KEY (or SESSION_SECRET).' }, 500);
  }

  const secretEnc = await encryptText(encKey, secret);
  await upsertUserPendingTotp(env.DB, partial.email, secretEnc);

  return json({
    ok: true,
    email: partial.email,
    secret,
    otpauthUrl: otpauthUri({ secret, email: partial.email }),
  });
}

async function totpConfirm(request, env) {
  const partial = await readPartialSession(env, request);
  if (!partial) return json({ error: 'Email verification required first.' }, 401);

  const body = await readJson(request);
  const code = String(body?.code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(code)) {
    return json({ error: 'Enter the 6-digit authenticator code.' }, 400);
  }

  const user = await getUser(env.DB, partial.email);
  if (!user?.totp_secret_enc) {
    return json({ error: 'Start authenticator setup first.' }, 400);
  }

  const encKey = env.TOTP_ENCRYPTION_KEY || env.SESSION_SECRET;
  const secret = await decryptText(encKey, user.totp_secret_enc);
  const ok = await verifyTotp(secret, code);
  if (!ok) return json({ error: 'Incorrect authenticator code.' }, 401);

  await confirmUserTotp(env.DB, partial.email);
  const entry = await getAllowlistEntry(env.DB, partial.email);
  if (!entry) {
    return json({ error: 'This email is not allowed to sign in.' }, 403);
  }

  await destroyPartialSession(env, request);
  const sid = await createFullSession(env, partial.email, entry.role);

  return withCookies(
    json({
      ok: true,
      email: partial.email,
      role: entry.role,
      next: 'app',
    }),
    [...clearAuthCookies(), setSessionCookie(sid)],
  );
}

async function totpVerify(request, env) {
  const partial = await readPartialSession(env, request);
  if (!partial) return json({ error: 'Email verification required first.' }, 401);

  const body = await readJson(request);
  const code = String(body?.code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(code)) {
    return json({ error: 'Enter the 6-digit authenticator code.' }, 400);
  }

  const okRl = await rateLimit(env, `totp:${partial.email}`, 30, 60 * 60);
  if (!okRl) return json({ error: 'Too many attempts. Try again later.' }, 429);

  const entry = await getAllowlistEntry(env.DB, partial.email);
  if (!entry) {
    return json({ error: 'This email is not allowed to sign in.' }, 403);
  }

  const user = await getUser(env.DB, partial.email);
  if (!user?.totp_confirmed || !user.totp_secret_enc) {
    return json({ error: 'Authenticator not enrolled.', next: 'totp_setup' }, 400);
  }

  const encKey = env.TOTP_ENCRYPTION_KEY || env.SESSION_SECRET;
  const secret = await decryptText(encKey, user.totp_secret_enc);
  const ok = await verifyTotp(secret, code);
  if (!ok) return json({ error: 'Incorrect authenticator code.' }, 401);

  await destroyPartialSession(env, request);
  const sid = await createFullSession(env, partial.email, entry.role);

  return withCookies(
    json({
      ok: true,
      email: partial.email,
      role: entry.role,
      next: 'app',
    }),
    [...clearAuthCookies(), setSessionCookie(sid)],
  );
}

async function me(request, env) {
  const full = await readFullSession(env, request);
  if (full) {
    return json({
      authenticated: true,
      email: full.email,
      role: full.role,
      totpOk: true,
      isAdmin: full.role === 'admin',
    });
  }

  const partial = await readPartialSession(env, request);
  if (partial) {
    const user = await getUser(env.DB, partial.email);
    const needsTotpSetup = !user || !user.totp_confirmed || !user.totp_secret_enc;
    return json({
      authenticated: false,
      emailVerified: true,
      email: partial.email,
      needsTotpSetup,
      next: needsTotpSetup ? 'totp_setup' : 'totp_verify',
    });
  }

  return json({ authenticated: false }, 401);
}

async function logout(request, env) {
  await destroyFullSession(env, request);
  await destroyPartialSession(env, request);
  return withCookies(json({ ok: true }), clearAuthCookies());
}
