export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers,
    },
  });
}

export function withCookies(response, cookies) {
  const headers = new Headers(response.headers);
  for (const c of Array.isArray(cookies) ? cookies : [cookies]) {
    if (c) headers.append('Set-Cookie', c);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export function methodNotAllowed(allowed) {
  return json({ error: 'Method not allowed' }, 405, { Allow: allowed });
}
