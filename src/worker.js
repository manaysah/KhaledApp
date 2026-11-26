import { readFullSession, readPartialSession } from './lib/session.js';
import { handleAuth } from './routes/auth.js';
import { handleAdmin } from './routes/admin.js';
import { json } from './lib/http.js';

/** Canonical login path — never bounce this through a clean-URL redirect. */
const LOGIN_HTML = '/login.html';
const LOGIN_PATHS = new Set(['/login', '/login.html']);
const ADMIN_PATHS = new Set(['/admin', '/admin.html']);
const PUBLIC_EXACT = new Set(['/favicon.ico', '/robots.txt']);
const PUBLIC_PREFIXES = ['/assets/'];

function normalizePathname(pathname) {
  if (!pathname) return '/';
  if (pathname.length > 1 && pathname.endsWith('/')) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

function isPublicPath(pathname) {
  if (LOGIN_PATHS.has(pathname) || PUBLIC_EXACT.has(pathname)) return true;
  return PUBLIC_PREFIXES.some((p) => pathname.startsWith(p));
}

function redirect(url) {
  return Response.redirect(url, 302);
}

function loginUrl(baseUrl, search = '') {
  const next = new URL(LOGIN_HTML, baseUrl);
  if (search) next.search = search.startsWith('?') ? search.slice(1) : search;
  return next.toString();
}

/** Fetch a static asset by path without relying on Assets HTML extension redirects. */
function serveAsset(env, request, assetPath) {
  const url = new URL(request.url);
  url.pathname = assetPath;
  // Drop conditional headers that could confuse a rewritten asset request
  const headers = new Headers(request.headers);
  headers.delete('if-none-match');
  headers.delete('if-modified-since');
  return env.ASSETS.fetch(new Request(url.toString(), { method: request.method, headers }));
}

function missingBindings(env) {
  const missing = [];
  if (!env.DB) missing.push('DB (D1)');
  if (!env.AUTH_KV) missing.push('AUTH_KV (KV)');
  if (!env.ASSETS) missing.push('ASSETS');
  return missing;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = normalizePathname(url.pathname);

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
      return handleAuth(request, env, pathname, ctx);
    }

    if (pathname === '/api/admin/allowlist' || pathname.startsWith('/api/admin/')) {
      return handleAdmin(request, env);
    }

    if (pathname.startsWith('/api/')) {
      return json({ error: 'Not found' }, 404);
    }

    // Login must always 200 the HTML — never redirect to another login variant
    if (LOGIN_PATHS.has(pathname)) {
      return serveAsset(env, request, LOGIN_HTML);
    }

    if (isPublicPath(pathname)) {
      return serveAsset(env, request, pathname === '/' ? '/index.html' : pathname);
    }

    if (ADMIN_PATHS.has(pathname)) {
      const session = await readFullSession(env, request);
      if (!session) return redirect(loginUrl(url));
      if (session.role !== 'admin') return redirect(new URL('/', url).toString());
      return serveAsset(env, request, '/admin.html');
    }

    const session = await readFullSession(env, request);
    if (session) {
      const assetPath =
        pathname === '/' || pathname === '/index.html' ? '/index.html' : pathname;
      return serveAsset(env, request, assetPath);
    }

    const partial = await readPartialSession(env, request);
    if (partial) {
      return redirect(loginUrl(url, 'step=totp'));
    }

    return redirect(loginUrl(url));
  },
};
