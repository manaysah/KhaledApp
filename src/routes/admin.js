import { normalizeEmail, isValidEmail, isAdminEmail } from '../lib/email.js';
import { listAllowlist, addAllowlist, removeAllowlist } from '../lib/db.js';
import { readFullSession } from '../lib/session.js';
import { json, readJson, methodNotAllowed } from '../lib/http.js';

async function requireAdmin(request, env) {
  const session = await readFullSession(env, request);
  if (!session) return { error: json({ error: 'Sign in required.' }, 401) };
  if (session.role !== 'admin' && !isAdminEmail(session.email)) {
    return { error: json({ error: 'Admin only.' }, 403) };
  }
  return { session };
}

export async function handleAdmin(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const method = request.method;

  if (method === 'GET') {
    const entries = await listAllowlist(env.DB);
    return json({ ok: true, entries });
  }

  if (method === 'POST') {
    const body = await readJson(request);
    const email = normalizeEmail(body?.email);
    if (!isValidEmail(email)) {
      return json({ error: 'Enter a valid email address.' }, 400);
    }
    const entry = await addAllowlist(env.DB, email, auth.session.email);
    return json({ ok: true, entry });
  }

  if (method === 'DELETE') {
    const url = new URL(request.url);
    const email = normalizeEmail(url.searchParams.get('email') || '');
    if (!isValidEmail(email)) {
      return json({ error: 'Email required.' }, 400);
    }
    const result = await removeAllowlist(env.DB, email);
    if (!result.ok) return json({ error: result.error }, 400);
    return json({ ok: true });
  }

  return methodNotAllowed('GET, POST, DELETE');
}
