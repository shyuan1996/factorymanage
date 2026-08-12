const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const dataDir = path.join(root, 'data');
const stateFile = path.join(dataDir, 'state.json');
const port = Number(process.env.PORT || 4173);

function loadDotEnv() {
  const envFile = path.join(root, '.env');
  if (!fs.existsSync(envFile)) return;
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator < 1) continue;
    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!process.env[key]) process.env[key] = value;
  }
}

loadDotEnv();

const authUsername = process.env.FACTORY_USERNAME || 'admin';
const authPassword = process.env.FACTORY_PASSWORD || 'change-me-before-deploy';
const authPasswordHash = process.env.FACTORY_PASSWORD_HASH || '';
const sessionSecret = process.env.FACTORY_SESSION_SECRET || 'local-development-only-change-this-secret';
const sessionMaxAge = 30 * 24 * 60 * 60;

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

function send(res, status, type, body, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extraHeaders });
  res.end(body);
}

function sendJson(res, status, value, extraHeaders = {}) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(value), extraHeaders);
}

function safePath(urlPath) {
  const requested = urlPath === '/' ? '/index.html' : urlPath;
  const target = path.resolve(root, '.' + requested);
  return target.startsWith(path.resolve(root)) ? target : null;
}

function passwordDigest(value) {
  return crypto.scryptSync(String(value), sessionSecret, 32).toString('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validCredentials(username, password) {
  if (!safeEqual(username, authUsername)) return false;
  const expected = authPasswordHash || passwordDigest(authPassword);
  return safeEqual(passwordDigest(password), expected);
}

function parseCookies(req) {
  const cookies = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try { cookies[key] = decodeURIComponent(value); } catch { cookies[key] = value; }
  }
  return cookies;
}

function sessionToken(username) {
  const payload = Buffer.from(JSON.stringify({ username, expiresAt: Date.now() + sessionMaxAge * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function sessionUsername(req) {
  const token = parseCookies(req).factory_session;
  if (!token) return null;
  const separator = token.lastIndexOf('.');
  if (separator < 1) return null;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  if (!safeEqual(signature, expected)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return parsed.username === authUsername && Number(parsed.expiresAt) > Date.now() ? parsed.username : null;
  } catch { return null; }
}

function isSecureRequest(req) {
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return forwarded === 'https' || Boolean(req.socket.encrypted);
}

function authCookie(req, token, maxAge = sessionMaxAge) {
  const secure = isSecureRequest(req) ? '; Secure' : '';
  return `factory_session=${encodeURIComponent(token)}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Path=/${secure}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5_000_000) reject(new Error('Request too large'));
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  const pathname = requestUrl.pathname;

  if (pathname === '/auth/login' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const contentType = String(req.headers['content-type'] || '');
      const values = contentType.includes('application/json') ? JSON.parse(body || '{}') : Object.fromEntries(new URLSearchParams(body));
      if (!validCredentials(values.username, values.password)) {
        sendJson(res, 401, { ok: false, error: '帳號或密碼錯誤' });
        return;
      }
      sendJson(res, 200, { ok: true, expiresIn: sessionMaxAge }, { 'Set-Cookie': authCookie(req, sessionToken(authUsername)) });
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error.message });
    }
    return;
  }

  if (pathname === '/auth/session' && req.method === 'GET') {
    sendJson(res, 200, { authenticated: Boolean(sessionUsername(req)), expiresIn: sessionMaxAge });
    return;
  }

  if (pathname === '/auth/logout' && (req.method === 'POST' || req.method === 'GET')) {
    sendJson(res, 200, { ok: true }, { 'Set-Cookie': authCookie(req, '', 0) });
    return;
  }

  const authenticated = Boolean(sessionUsername(req));
  const protectedRequest = pathname === '/' || pathname === '/index.html' || pathname === '/api/state' || pathname.startsWith('/data/');
  if (!authenticated && protectedRequest) {
    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      fs.readFile(path.join(root, 'login.html'), (err, content) => err ? send(res, 500, 'text/plain; charset=utf-8', err.message) : send(res, 200, 'text/html; charset=utf-8', content));
    } else {
      sendJson(res, 401, { ok: false, error: '需要登入' });
    }
    return;
  }

  if (pathname === '/api/state' && req.method === 'GET') {
    fs.readFile(stateFile, (err, content) => err ? send(res, 500, 'text/plain; charset=utf-8', err.message) : send(res, 200, 'application/json; charset=utf-8', content));
    return;
  }

  if (pathname === '/api/state' && req.method === 'PUT') {
    try {
      const parsed = JSON.parse(await readBody(req));
      if (!parsed || !Array.isArray(parsed.masters) || !Array.isArray(parsed.projects)) throw new Error('Invalid state payload');
      const temporary = stateFile + '.tmp';
      fs.writeFileSync(temporary, JSON.stringify(parsed, null, 2), 'utf8');
      fs.renameSync(temporary, stateFile);
      sendJson(res, 200, { ok: true });
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error.message });
    }
    return;
  }

  if (req.method !== 'GET') { send(res, 405, 'text/plain; charset=utf-8', 'Method Not Allowed'); return; }
  if (pathname === '/login.html') {
    fs.readFile(path.join(root, 'login.html'), (err, content) => err ? send(res, 500, 'text/plain; charset=utf-8', err.message) : send(res, 200, 'text/html; charset=utf-8', content));
    return;
  }
  if (pathname !== '/' && pathname !== '/index.html') { send(res, 404, 'text/plain; charset=utf-8', 'Not Found'); return; }
  const file = safePath(pathname);
  if (!file) { send(res, 403, 'text/plain; charset=utf-8', 'Forbidden'); return; }
  fs.readFile(file, (err, content) => err ? send(res, 404, 'text/plain; charset=utf-8', 'Not Found') : send(res, 200, 'text/html; charset=utf-8', content));
});

server.listen(port, process.env.HOST || '0.0.0.0', () => console.log(`Factory Workboard: http://127.0.0.1:${port}`));
