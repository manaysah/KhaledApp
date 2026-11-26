import { readFullSession, readPartialSession } from './lib/session.js';
import { handleAuth } from './routes/auth.js';
import { handleAdmin } from './routes/admin.js';
import { json } from './lib/http.js';

// Assets default html_handling serves /login.html as /login (and 307s .html → extensionless).
// Treat both as public so auth redirects never loop.
const PUBLIC_EXACT = new Set([
  '/login',
  '/login.html',
  '/favicon.ico',
  '/robots.txt',
]);
const PUBLIC_PREFIXES = ['/assets/'];

function isPublicAsset(pathname) {
  if (PUBLIC_EXACT.has(pathname)) return true;
  return PUBLIC_PREFIXES.some((p) => pathname.startsWith(p));
}

function redirect(url) {
  return Response.redirect(url, 302);
}

function loginUrl(url, search = '') {
  const target = new URL('/login', url);
  if (search) target.search = search.startsWith('?') ? search.slice(1) : search;
  return target.toString();
}

function missingBindings(env) {
  const missing = [];
  if (!env.DB) missing.push('DB (D1)');
  if (!env.AUTH_KV) missing.push('AUTH_KV (KV)');
  if (!env.ASSETS) missing.push('ASSETS');
  return missing;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    const missing = missingBindings(env);
    if (missing.length && pathname.startsWith('/api/')) {
      return json(
        {
          error: `Worker missing bindings: ${missing.join(', ')}. Configure them in wrangler.toml / dashboard.`,
        },
        503,
      );
    }

    if (pathname.startsWith('/api/auth/')) {
      return handleAuth(request, env, pathname);
    }

    if (pathname === '/api/admin/allowlist' || pathname.startsWith('/api/admin/')) {
      return handleAdmin(request, env);
    }

    if (pathname.startsWith('/api/')) {
      return json({ error: 'Not found' }, 404);
    }

    // Static / HTML
    if (isPublicAsset(pathname)) {
      return env.ASSETS.fetch(request);
    }

    if (pathname === '/admin' || pathname === '/admin.html') {
      const session = await readFullSession(env, request);
      if (!session) return redirect(loginUrl(url));
      if (session.role !== 'admin') return redirect(new URL('/', url).toString());
      return env.ASSETS.fetch(request);
    }

    const session = await readFullSession(env, request);
    if (session) return env.ASSETS.fetch(request);

    const partial = await readPartialSession(env, request);
    if (partial) {
      return redirect(loginUrl(url, 'step=totp'));
    }

    return redirect(loginUrl(url));
  },
};
