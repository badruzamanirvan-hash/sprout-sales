/**
 * Sprout Sales Tracker — Cloudflare Worker Proxy
 *
 * Secrets to set in Cloudflare Dashboard → Worker → Settings → Variables and Secrets:
 *   AIRTABLE_TOKEN     Personal Access Token from airtable.com/create/tokens
 *   AIRTABLE_BASE_ID   Your Base ID (starts with "app...")
 *   ADMIN_PASSWORD     6-digit PIN for Admin login
 *   HEAD_PASSWORD      6-digit PIN for Head of Sales login
 *   SALES_PASSWORD     6-digit PIN for Sales (generic) login
 *   FINANCE_PASSWORD   6-digit PIN for Finance login
 *   ALLOWED_ORIGIN     Your GitHub Pages URL, e.g. https://irfan-badruzaman.github.io
 */

const AIRTABLE_API = 'https://api.airtable.com/v0';

function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || '';
  const allowedOrigin = (!allowed || allowed === '*' || origin === allowed)
    ? (origin || '*')
    : allowed;
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

async function handleRequest(request, env) {
  const origin = request.headers.get('Origin') || '';
  const url    = new URL(request.url);
  const path   = url.pathname;

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
  }

  // ── POST /login ──────────────────────────────────────────────
  if (path === '/login' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return Response.json({ ok: false }, { status: 400, headers: corsHeaders(origin, env) }); }

    const { role, password } = body;
    const ROLE_MAP = {
      admin:   env.ADMIN_PASSWORD,
      head:    env.HEAD_PASSWORD,
      sales:   env.SALES_PASSWORD,
      finance: env.FINANCE_PASSWORD,
    };
    const expected = ROLE_MAP[role];
    const ok = !!(expected && password === expected);
    return Response.json({ ok }, { headers: corsHeaders(origin, env) });
  }

  // ── /airtable/:table[/:recordId][?params] ────────────────────
  const match = path.match(/^\/airtable\/([^/]+)(?:\/([^/]+))?$/);
  if (match) {
    const table    = decodeURIComponent(match[1]);
    const recordId = match[2];
    const baseId   = env.AIRTABLE_BASE_ID;
    const token    = env.AIRTABLE_TOKEN;

    if (!baseId || !token) {
      return Response.json(
        { error: 'Worker secrets not configured. Set AIRTABLE_BASE_ID and AIRTABLE_TOKEN.' },
        { status: 500, headers: corsHeaders(origin, env) }
      );
    }

    let atUrl = `${AIRTABLE_API}/${baseId}/${encodeURIComponent(table)}`;
    if (recordId) atUrl += `/${recordId}`;
    if (url.search) atUrl += url.search;

    const init = {
      method: request.method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    };

    if (['POST', 'PATCH'].includes(request.method)) {
      init.body = await request.text();
    }

    const atRes  = await fetch(atUrl, init);
    const atBody = await atRes.text();

    return new Response(atBody, {
      status: atRes.status,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin, env) },
    });
  }

  return new Response('Not Found', { status: 404, headers: corsHeaders(origin, env) });
}

export default { fetch: handleRequest };
