/** Normalize emails; treat bare @gmail as @gmail.com. */
export function normalizeEmail(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let email = raw.trim().toLowerCase();
  if (!email) return '';
  if (email.endsWith('@gmail')) email = `${email}.com`;
  return email;
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export const ADMIN_EMAIL = 'mhmd.manaysah@gmail.com';

export function isAdminEmail(email) {
  return normalizeEmail(email) === ADMIN_EMAIL;
}

/** Who receives allowlist access alerts (defaults to site admin). */
export function accessNotifyRecipient(env) {
  const configured = env.ACCESS_NOTIFY_EMAIL ? normalizeEmail(env.ACCESS_NOTIFY_EMAIL) : '';
  return configured || ADMIN_EMAIL;
}

async function sendResendMessage(env, { to, subject, text, html }) {
  if (env.AUTH_DEV_MODE === 'true' || env.AUTH_DEV_MODE === true) {
    console.log('email skip (dev)', { to, subject });
    return { ok: true, mode: 'dev' };
  }

  const apiKey = env.RESEND_API_KEY;
  const from = env.EMAIL_FROM;
  if (!apiKey || !from) {
    return { ok: false, error: 'Email delivery is not configured.' };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to: [to], subject, text, html }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error('Resend error', res.status, body);
    return { ok: false, error: 'Failed to send email.' };
  }

  return { ok: true, mode: 'resend' };
}

/**
 * Alert the site owner when an allowlisted member starts sign-in or completes it.
 * event: 'sign_in_started' | 'signed_in'
 */
export async function notifyAllowlistAccess(env, request, { email, event, role }) {
  const actor = normalizeEmail(email);
  if (!actor) return { ok: false, error: 'missing email' };

  const to = accessNotifyRecipient(env);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const country = request.headers.get('CF-IPCountry') || '';
  const when = new Date().toISOString();

  const started = event === 'sign_in_started';
  const subject = started
    ? `Our Little Tide: sign-in attempt — ${actor}`
    : `Our Little Tide: ${actor} signed in`;

  const lines = [
    started
      ? `An allowlisted family member started signing in to Our Little Tide.`
      : `An allowlisted family member completed sign-in and can access the site.`,
    '',
    `Email: ${actor}`,
    `Role: ${role || 'member'}`,
    `Time (UTC): ${when}`,
    `IP: ${ip}${country ? ` (${country})` : ''}`,
    '',
    'This is an automated security notice for the family site.',
  ];
  const text = lines.join('\n');
  const html = lines.map((l) => (l ? `<p>${l}</p>` : '')).join('');

  return sendResendMessage(env, { to, subject, text, html });
}

/**
 * Send a one-time login code.
 * Production: Resend (RESEND_API_KEY + EMAIL_FROM).
 * Dev: AUTH_DEV_MODE=true skips send; caller may echo the code.
 */
export async function sendLoginCode(env, to, code) {
  return sendResendMessage(env, {
    to,
    subject: 'Your Our Little Tide login code',
    text: `Your login code is ${code}. It expires in 10 minutes.\n\nIf you did not request this, ignore this email.`,
    html: `<p>Your login code is <strong style="font-size:20px;letter-spacing:2px">${code}</strong>.</p><p>It expires in 10 minutes.</p><p>If you did not request this, ignore this email.</p>`,
  });
}
