const SESSION_MAX_AGE = 30 * 24 * 60 * 60;
const COOKIE_NAME = 'factory_session';

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function base64UrlEncode(value) {
  return bytesToBase64Url(new TextEncoder().encode(value));
}

function base64UrlDecode(value) {
  return new TextDecoder().decode(base64UrlToBytes(value));
}

async function digest(value) {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))));
}

function equalText(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.length !== b.length) return false;
  let result = 0;
  for (let index = 0; index < a.length; index += 1) result |= a[index] ^ b[index];
  return result === 0;
}

function cookies(request) {
  const result = {};
  for (const part of String(request.headers.get('Cookie') || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch { result[key] = value; }
  }
  return result;
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers } });
}

function cookieHeader(token, request, maxAge = SESSION_MAX_AGE) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Path=/${secure}`;
}

async function passwordMatches(password, env) {
  const secret = String(env.FACTORY_SESSION_SECRET || 'change-this-secret-before-deploy');
  const candidate = await digest(`${secret}:${String(password)}`);
  if (env.FACTORY_PASSWORD_HASH) return equalText(candidate, env.FACTORY_PASSWORD_HASH);
  return env.FACTORY_PASSWORD ? equalText(String(password), String(env.FACTORY_PASSWORD)) : false;
}

async function createSession(username, env) {
  const expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
  const payload = base64UrlEncode(JSON.stringify({ username, expiresAt }));
  const signature = await sign(payload, String(env.FACTORY_SESSION_SECRET || 'change-this-secret-before-deploy'));
  return `${payload}.${signature}`;
}

async function sessionUsername(request, env) {
  const token = cookies(request)[COOKIE_NAME];
  if (!token) return null;
  const separator = token.lastIndexOf('.');
  if (separator < 1) return null;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expected = await sign(payload, String(env.FACTORY_SESSION_SECRET || 'change-this-secret-before-deploy'));
  if (!equalText(signature, expected)) return null;
  try {
    const value = JSON.parse(base64UrlDecode(payload));
    return value.username === String(env.FACTORY_USERNAME || '') && Number(value.expiresAt) > Date.now() ? value.username : null;
  } catch { return null; }
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

async function readState(env) {
  if (!env.DB) throw new Error('D1 binding DB is not configured');
  const row = await env.DB.prepare('SELECT state_json FROM app_state WHERE id = 1').first();
  return row?.state_json ? JSON.parse(row.state_json) : { masters: [], projects: [], overtime: {} };
}

async function writeState(env, state) {
  if (!env.DB) throw new Error('D1 binding DB is not configured');
  await env.DB.prepare('INSERT INTO app_state (id, state_json, updated_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at').bind(JSON.stringify(state), new Date().toISOString()).run();
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/auth/login' && request.method === 'POST') {
    const body = await readJson(request);
    const username = String(body?.username || '');
    const password = String(body?.password || '');
    const validUser = env.FACTORY_USERNAME && equalText(username, String(env.FACTORY_USERNAME));
    if (!validUser || !(await passwordMatches(password, env))) return json({ ok: false, error: '帳號或密碼錯誤' }, 401);
    return json({ ok: true, expiresIn: SESSION_MAX_AGE }, 200, { 'Set-Cookie': cookieHeader(await createSession(username, env), request) });
  }

  if (path === '/auth/session' && request.method === 'GET') return json({ authenticated: Boolean(await sessionUsername(request, env)), expiresIn: SESSION_MAX_AGE });

  if (path === '/auth/logout' && (request.method === 'POST' || request.method === 'GET')) return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', request, 0) });

  const authenticated = Boolean(await sessionUsername(request, env));
  if (path === '/api/state') {
    if (!authenticated) return json({ ok: false, error: '需要登入' }, 401);
    try {
      if (request.method === 'GET') return json(await readState(env));
      if (request.method === 'PUT') {
        const state = await readJson(request);
        if (!state || !Array.isArray(state.masters) || !Array.isArray(state.projects)) return json({ ok: false, error: '資料格式不正確' }, 400);
        await writeState(env, state);
        return json({ ok: true });
      }
      return json({ ok: false, error: 'Method Not Allowed' }, 405);
    } catch (error) {
      return json({ ok: false, error: error.message }, 500);
    }
  }

  if (!authenticated && (path === '/' || path === '/index.html')) return Response.redirect(new URL('/login.html', request.url), 302);
  return next();
}
