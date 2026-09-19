/**
 * Sprout Sales Tracker — Cloudflare Worker Proxy
 *
 * Secrets to set in Cloudflare Dashboard → Worker → Settings → Variables and Secrets:
 *   AIRTABLE_TOKEN     Personal Access Token from airtable.com/create/tokens
 *   AIRTABLE_BASE_ID   Your Base ID (starts with "app...")
 *   ADMIN_PASSWORD     PIN for Admin login
 *   HEAD_PASSWORD      PIN for Head of Sales login
 *   SALES_PASSWORD     PIN for Sales (generic) login
 *   FINANCE_PASSWORD   PIN for Finance login
 *   SESSION_SECRET     long random string used to sign session tokens  <-- NEW, REQUIRED
 *   ALLOWED_ORIGIN     Your GitHub Pages URL
 *
 * Security model:
 *   /login          verifies a role PIN and returns a signed, expiring token.
 *   /airtable/*     REQUIRES a valid token. Without one it returns 401 and never
 *                   touches Airtable. CORS is not a security control, so the token
 *                   is what actually protects the data.
 */

const AIRTABLE_API = 'https://api.airtable.com/v0';
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

const enc = new TextEncoder();

function b64url(bytes) {
  let s = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToString(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return atob(p + '='.repeat((4 - (p.length % 4)) % 4));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function sign(payload, secret) {
  return b64url(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payload)));
}

// length-independent comparison so we do not leak how much of a value matched
function timingSafeEqual(a, b) {
  const x = String(a), y = String(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  return diff === 0;
}

async function issueToken(role, secret) {
  const payload = b64url(enc.encode(JSON.stringify({ role, exp: Date.now() + TOKEN_TTL_MS })));
  return payload + '.' + (await sign(payload, secret));
}

async function verifyToken(token, secret) {
  if (!secret || typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 1) return null;
  const payload = token.slice(0, i);
  if (!timingSafeEqual(token.slice(i + 1), await sign(payload, secret))) return null;
  try {
    const data = JSON.parse(b64urlToString(payload));
    if (!data || typeof data.exp !== 'number' || data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

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
  const cors   = corsHeaders(origin, env);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  // ── POST /login ──────────────────────────────────────────────
  if (path === '/login' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return Response.json({ ok: false }, { status: 400, headers: cors }); }

    if (!env.SESSION_SECRET) {
      return Response.json({ ok: false, error: 'SESSION_SECRET not configured' }, { status: 500, headers: cors });
    }

    const { role, password } = body;
    const ROLE_MAP = {
      admin:   env.ADMIN_PASSWORD,
      head:    env.HEAD_PASSWORD,
      sales:   env.SALES_PASSWORD,
      finance: env.FINANCE_PASSWORD,
    };
    const expected = ROLE_MAP[role];
    if (!expected || !timingSafeEqual(password, expected)) {
      return Response.json({ ok: false }, { status: 401, headers: cors });
    }

    return Response.json(
      { ok: true, token: await issueToken(role, env.SESSION_SECRET), role, expires_in: TOKEN_TTL_MS / 1000 },
      { headers: cors }
    );
  }

  // ── /airtable/:table[/:recordId] — token required ────────────
  const match = path.match(/^\/airtable\/([^/]+)(?:\/([^/]+))?$/);
  if (match) {
    // Fail closed: no secret configured means no access, never open access.
    if (!env.SESSION_SECRET) {
      return Response.json({ error: 'Server not configured for authentication.' }, { status: 500, headers: cors });
    }

    const auth = request.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const session = await verifyToken(token, env.SESSION_SECRET);

    if (!session) {
      return Response.json(
        { error: 'Not authenticated. Sign in to access this data.' },
        { status: 401, headers: cors }
      );
    }

    const table    = decodeURIComponent(match[1]);
    const recordId = match[2];
    const baseId   = env.AIRTABLE_BASE_ID;
    const atToken  = env.AIRTABLE_TOKEN;

    if (!baseId || !atToken) {
      return Response.json(
        { error: 'Worker secrets not configured. Set AIRTABLE_BASE_ID and AIRTABLE_TOKEN.' },
        { status: 500, headers: cors }
      );
    }

    let atUrl = `${AIRTABLE_API}/${baseId}/${encodeURIComponent(table)}`;
    if (recordId) atUrl += `/${recordId}`;
    if (url.search) atUrl += url.search;

    const init = {
      method: request.method,
      headers: { 'Authorization': `Bearer ${atToken}`, 'Content-Type': 'application/json' },
    };
    if (['POST', 'PATCH'].includes(request.method)) init.body = await request.text();

    const atRes  = await fetch(atUrl, init);
    const atBody = await atRes.text();

    return new Response(atBody, {
      status: atRes.status,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  return new Response('Not Found', { status: 404, headers: cors });
}

export default { fetch: handleRequest };
