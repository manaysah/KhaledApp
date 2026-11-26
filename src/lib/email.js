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

/**
 * Send a one-time login code.
 * Production: Resend (RESEND_API_KEY + EMAIL_FROM).
 * Dev: AUTH_DEV_MODE=true skips send; caller may echo the code.
 */
export async function sendLoginCode(env, to, code) {
  if (env.AUTH_DEV_MODE === 'true' || env.AUTH_DEV_MODE === true) {
    return { ok: true, mode: 'dev' };
  }

  const apiKey = env.RESEND_API_KEY;
  const from = env.EMAIL_FROM;
  if (!apiKey || !from) {
    return {
      ok: false,
      error: 'Email delivery is not configured (set RESEND_API_KEY and EMAIL_FROM).',
    };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: 'Your Our Little Tide login code',
      text: `Your login code is ${code}. It expires in 10 minutes.\n\nIf you did not request this, ignore this email.`,
      html: `<p>Your login code is <strong style="font-size:20px;letter-spacing:2px">${code}</strong>.</p><p>It expires in 10 minutes.</p><p>If you did not request this, ignore this email.</p>`,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error('Resend error', res.status, body);
    return { ok: false, error: 'Failed to send login email.' };
  }

  return { ok: true, mode: 'resend' };
}
