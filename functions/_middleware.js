const SESSION_MAX_AGE = 30 * 24 * 60 * 60;
const COOKIE_NAME = 'factory_session';
const DEFAULT_USERNAME = 'syadmin';
const MIN_PASSWORD_LENGTH = 10;

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

function randomSalt() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function authVersion() {
  return `${new Date().toISOString()}:${randomSalt()}`;
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
  const expires = maxAge > 0 ? new Date(Date.now() + maxAge * 1000).toUTCString() : new Date(0).toUTCString();
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${maxAge}; Expires=${expires}; HttpOnly; SameSite=Lax; Path=/${secure}`;
}

async function readAuthRecord(env) {
  if (!env.DB) return null;
  const row = await env.DB.prepare('SELECT username, password_salt, password_hash, updated_at FROM auth_settings WHERE id = 1').first();
  return row?.username && row?.password_salt && row?.password_hash ? {
    username: String(row.username),
    salt: String(row.password_salt),
    hash: String(row.password_hash),
    version: String(row.updated_at || 'db')
  } : null;
}

async function credentials(env) {
  const stored = await readAuthRecord(env);
  if (stored) return { ...stored, source: 'db' };
  return {
    username: String(env.FACTORY_USERNAME || DEFAULT_USERNAME),
    version: 'environment',
    source: 'environment',
    passwordHash: env.FACTORY_PASSWORD_HASH ? String(env.FACTORY_PASSWORD_HASH) : '',
    password: env.FACTORY_PASSWORD ? String(env.FACTORY_PASSWORD) : ''
  };
}

async function passwordMatches(password, env, record) {
  if (record.source === 'db') return equalText(await digest(`${record.salt}:${String(password)}`), record.hash);
  const secret = String(env.FACTORY_SESSION_SECRET || 'change-this-secret-before-deploy');
  if (record.passwordHash) return equalText(await digest(`${secret}:${String(password)}`), record.passwordHash);
  return record.password ? equalText(String(password), record.password) : false;
}

async function persistInitialPassword(env, record, password) {
  if (!env.DB || record.source === 'db') return record;
  const salt = randomSalt();
  const hash = await digest(`${salt}:${String(password)}`);
  const version = authVersion();
  await env.DB.prepare('INSERT INTO auth_settings (id, username, password_salt, password_hash, updated_at) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING').bind(record.username, salt, hash, version).run();
  return (await readAuthRecord(env)) || { username: record.username, salt, hash, version, source: 'db' };
}

async function createSession(username, authVersionValue, env) {
  const expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
  const payload = base64UrlEncode(JSON.stringify({ username, authVersion: authVersionValue, expiresAt }));
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
    const record = await credentials(env);
    return value.username === record.username && value.authVersion === record.version && Number(value.expiresAt) > Date.now() ? value.username : null;
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
    const record = await credentials(env);
    if (!equalText(username, record.username) || !(await passwordMatches(password, env, record))) return json({ ok: false, error: '帳號或密碼錯誤' }, 401);
    const active = await persistInitialPassword(env, record, password);
    return json({ ok: true, expiresIn: SESSION_MAX_AGE }, 200, { 'Set-Cookie': cookieHeader(await createSession(username, active.version, env), request) });
  }

  if (path === '/auth/session' && request.method === 'GET') {
    const username = await sessionUsername(request, env);
    return json({ authenticated: Boolean(username), username, expiresIn: SESSION_MAX_AGE });
  }

  if (path === '/auth/logout' && (request.method === 'POST' || request.method === 'GET')) return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', request, 0) });

  const authenticated = Boolean(await sessionUsername(request, env));
  if (path === '/auth/password' && request.method === 'POST') {
    if (!authenticated) return json({ ok: false, error: '需要登入' }, 401);
    const body = await readJson(request);
    const currentPassword = String(body?.currentPassword || '');
    const newPassword = String(body?.newPassword || '');
    if (newPassword.length < MIN_PASSWORD_LENGTH) return json({ ok: false, error: `新密碼至少需要 ${MIN_PASSWORD_LENGTH} 個字元` }, 400);
    if (newPassword === currentPassword) return json({ ok: false, error: '新密碼不可與目前密碼相同' }, 400);
    if (!env.DB) return json({ ok: false, error: '目前部署未設定 D1，無法變更密碼' }, 503);
    const record = await credentials(env);
    if (!(await passwordMatches(currentPassword, env, record))) return json({ ok: false, error: '目前密碼錯誤' }, 401);
    const active = record.source === 'db' ? record : await persistInitialPassword(env, record, currentPassword);
    const salt = randomSalt();
    const hash = await digest(`${salt}:${newPassword}`);
    const version = authVersion();
    await env.DB.prepare('UPDATE auth_settings SET username = ?, password_salt = ?, password_hash = ?, updated_at = ? WHERE id = 1').bind(active.username, salt, hash, version).run();
    return json({ ok: true, message: '密碼已更新' }, 200, { 'Set-Cookie': cookieHeader(await createSession(active.username, version, env), request) });
  }

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

  if (authenticated && request.method === 'GET' && (path === '/login' || path === '/login.html')) return Response.redirect(new URL('/', request.url), 302);
  if (!authenticated && (path === '/' || path === '/index.html')) return Response.redirect(new URL('/login.html', request.url), 302);
  return next();
}
