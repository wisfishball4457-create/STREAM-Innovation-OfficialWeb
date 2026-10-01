'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');

const root = __dirname;
const configFile = path.join(root, '.env');

if (process.env.NODE_ENV !== 'production') {
  try {
    const config = fsSync.readFileSync(configFile, 'utf8');
    for (const line of config.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!match || Object.hasOwn(process.env, match[1])) continue;
      process.env[match[1]] = match[2].replace(/^(?:"(.*)"|'(.*)')$/, (_, doubleQuoted, singleQuoted) =>
        doubleQuoted ?? singleQuoted ?? match[2]);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

const port = Number.parseInt(process.env.PORT || '3000', 10);
const host = process.env.HOST || '127.0.0.1';
const adminUsername = process.env.ADMIN_USERNAME?.trim() || '';
const adminPassword = process.env.ADMIN_PASSWORD || '';
const applicationKeyText = process.env.APPLICATION_DATA_KEY || '';
const applicationDirectory = process.env.APPLICATION_DATA_DIR || path.join(root, '.private-data');
const applicationFile = path.join(applicationDirectory, 'applications.enc');
const maxBodyBytes = 8 * 1024;
const requestWindowMs = 15 * 60 * 1000;
const maxRequestsPerWindow = 5;
const loginRequests = new Map();
const sessions = new Map();
const sessionLifetimeMs = 4 * 60 * 60 * 1000;
let applicationWriteQueue = Promise.resolve();

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}

const adminConfigured = Boolean(adminUsername && adminPassword && applicationKeyText);
let applicationKey = null;

if (adminConfigured) {
  if (adminUsername.length > 80 || adminPassword.length < 16 || adminPassword.length > 256) {
    throw new Error('Admin username must be at most 80 characters and password must be 16-256 characters.');
  }

  try {
    applicationKey = Buffer.from(applicationKeyText, 'base64');
  } catch {
    throw new Error('APPLICATION_DATA_KEY must be a base64-encoded 32-byte key.');
  }
  if (applicationKey.length !== 32 || applicationKey.toString('base64') !== applicationKeyText) {
    throw new Error('APPLICATION_DATA_KEY must be a base64-encoded 32-byte key.');
  }
}

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.webp', 'image/webp'],
  ['.ico', 'image/x-icon']
]);

function sendJson(response, status, data) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(data));
}

function rateLimited(request, limits, maximum) {
  const now = Date.now();
  if (limits.size > 1000) {
    for (const [address, entry] of limits) {
      if (now - entry.startedAt >= requestWindowMs) limits.delete(address);
    }
  }
  const address = request.socket.remoteAddress || 'unknown';
  const entry = limits.get(address);

  if (!entry || now - entry.startedAt >= requestWindowMs) {
    limits.set(address, { startedAt: now, count: 1 });
    return false;
  }

  entry.count += 1;
  return entry.count > maximum;
}

function constantTimeEqual(left, right) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

function originIsSameSite(request) {
  const origin = request.headers.origin;
  if (!origin) return false;

  try {
    return new URL(origin).host === request.headers.host &&
      request.headers['sec-fetch-site'] !== 'cross-site';
  } catch {
    return false;
  }
}

function isSecureRequest(request) {
  return Boolean(request.socket.encrypted) ||
    (process.env.TRUST_PROXY_TLS === 'true' && request.headers['x-forwarded-proto'] === 'https');
}

function sendPage(response, status, page) {
  response.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  });
  response.end(page);
}

async function readJsonBody(request) {
  let size = 0;
  const chunks = [];

  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    throw error;
  }
}

function queueApplicationWrite(operation) {
  const result = applicationWriteQueue.then(operation);
  applicationWriteQueue = result.catch(() => {});
  return result;
}

async function readApplications() {
  try {
    const encrypted = await fs.readFile(applicationFile);
    if (encrypted.length < 29) throw new Error('Invalid encrypted application file.');
    const iv = encrypted.subarray(0, 12);
    const tag = encrypted.subarray(12, 28);
    const ciphertext = encrypted.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', applicationKey, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const applications = JSON.parse(plaintext);
    if (!Array.isArray(applications)) throw new Error('Invalid application data.');
    return applications;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function writeApplications(applications) {
  const directory = path.dirname(applicationFile);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', applicationKey, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(applications)), cipher.final()]);
  const encrypted = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
  const temporaryFile = `${applicationFile}.${crypto.randomUUID()}.tmp`;

  try {
    await fs.writeFile(temporaryFile, encrypted, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporaryFile, applicationFile);
  } catch (error) {
    await fs.rm(temporaryFile, { force: true }).catch(() => {});
    throw error;
  }
}

function getSessionToken(request) {
  const cookie = request.headers.cookie || '';
  const tokenCookie = cookie.split(';').map(part => part.trim()).find(part =>
    part.startsWith('stream_admin_session='));
  return tokenCookie?.slice('stream_admin_session='.length) || '';
}

function authenticate(request) {
  const token = getSessionToken(request);
  const expiresAt = sessions.get(token);
  if (!expiresAt || expiresAt <= Date.now()) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function setSessionCookie(response, token, maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  response.setHeader('Set-Cookie',
    `stream_admin_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure}`);
}

async function handleAdminLogin(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return sendJson(response, 405, { error: 'Use POST to sign in.' });
  }
  if (!adminConfigured) return sendJson(response, 503, { error: 'Private inbox is not configured.' });
  if (process.env.NODE_ENV === 'production' && !isSecureRequest(request)) {
    return sendJson(response, 426, { error: 'Administrator sign-in requires HTTPS.' });
  }
  if (!originIsSameSite(request)) return sendJson(response, 403, { error: 'Cross-site requests are not allowed.' });
  if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
    return sendJson(response, 415, { error: 'Send sign-in details as JSON.' });
  }
  if (rateLimited(request, loginRequests, maxRequestsPerWindow)) {
    return sendJson(response, 429, { error: 'Too many sign-in attempts. Try again later.' });
  }

  let body;
  try {
    body = await readJsonBody(request);
  } catch (error) {
    return sendJson(response, error.statusCode || 400, { error: error.message });
  }

  if (!body || typeof body.username !== 'string' || typeof body.password !== 'string' ||
      !constantTimeEqual(body.username, adminUsername) ||
      !constantTimeEqual(body.password, adminPassword)) {
    return sendJson(response, 401, { error: 'Invalid username or password.' });
  }

  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, Date.now() + sessionLifetimeMs);
  setSessionCookie(response, token, sessionLifetimeMs / 1000);
  return sendJson(response, 200, { success: true });
}

async function handleAdminApi(request, response, pathname) {
  if (pathname === '/api/admin/login') return handleAdminLogin(request, response);
  if (process.env.NODE_ENV === 'production' && !isSecureRequest(request)) {
    return sendJson(response, 426, { error: 'Private inbox access requires HTTPS.' });
  }
  if (pathname === '/api/admin/session') {
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return sendJson(response, 405, { error: 'Use GET to check the admin session.' });
    }
    if (!adminConfigured) return sendJson(response, 503, { error: 'Private inbox is not configured.' });
    return sendJson(response, 200, { authenticated: authenticate(request) });
  }
  if (!authenticate(request)) return sendJson(response, 401, { error: 'Sign in to access the private inbox.' });

  if (pathname === '/api/admin/applications' && request.method === 'GET') {
    try {
      const applications = await readApplications();
      return sendJson(response, 200, { applications });
    } catch (error) {
      console.error(`Could not read private applications (${error.code || error.name}).`);
      return sendJson(response, 500, { error: 'The private inbox could not be read.' });
    }
  }

  if (pathname === '/api/admin/applications' && request.method === 'PATCH') {
    if (!originIsSameSite(request)) return sendJson(response, 403, { error: 'Cross-site requests are not allowed.' });
    if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
      return sendJson(response, 415, { error: 'Send the update as JSON.' });
    }
    let body;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      return sendJson(response, error.statusCode || 400, { error: error.message });
    }
    if (typeof body?.id !== 'string' || !['new', 'reviewed'].includes(body.status)) {
      return sendJson(response, 400, { error: 'Provide a valid application ID and status.' });
    }
    try {
      const updated = await queueApplicationWrite(async () => {
        const applications = await readApplications();
        const entry = applications.find(application => application.id === body.id);
        if (!entry) return false;
        entry.status = body.status;
        await writeApplications(applications);
        return true;
      });
      return updated
        ? sendJson(response, 200, { success: true })
        : sendJson(response, 404, { error: 'Application not found.' });
    } catch (error) {
      console.error(`Could not update private application (${error.code || error.name}).`);
      return sendJson(response, 500, { error: 'The application could not be updated.' });
    }
  }

  if (pathname === '/api/admin/applications' && request.method === 'DELETE') {
    if (!originIsSameSite(request)) return sendJson(response, 403, { error: 'Cross-site requests are not allowed.' });
    if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
      return sendJson(response, 415, { error: 'Send the deletion request as JSON.' });
    }
    let body;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      return sendJson(response, error.statusCode || 400, { error: error.message });
    }
    if (typeof body?.id !== 'string') {
      return sendJson(response, 400, { error: 'Provide a valid application ID.' });
    }
    try {
      const deleted = await queueApplicationWrite(async () => {
        const applications = await readApplications();
        const remaining = applications.filter(application => application.id !== body.id);
        if (remaining.length === applications.length) return false;
        await writeApplications(remaining);
        return true;
      });
      return deleted
        ? sendJson(response, 200, { success: true })
        : sendJson(response, 404, { error: 'Application not found.' });
    } catch (error) {
      console.error(`Could not delete private application (${error.code || error.name}).`);
      return sendJson(response, 500, { error: 'The application could not be deleted.' });
    }
  }

  if (pathname === '/api/admin/logout' && request.method === 'POST') {
    if (!originIsSameSite(request)) return sendJson(response, 403, { error: 'Cross-site requests are not allowed.' });
    sessions.delete(getSessionToken(request));
    setSessionCookie(response, '', 0);
    return sendJson(response, 200, { success: true });
  }

  response.setHeader('Allow', pathname === '/api/admin/applications' ? 'GET, PATCH, DELETE' : 'GET, POST');
  return sendJson(response, 405, { error: 'Method not allowed.' });
}

async function sendAdminPage(response) {
  try {
    const page = await fs.readFile(path.join(root, 'admin.html'));
    return sendPage(response, 200, page);
  } catch (error) {
    if (error.code === 'ENOENT') {
      response.writeHead(404);
      return response.end('Admin page not found');
    }
    throw error;
  }
}

async function serveFile(request, response, pathname) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.setHeader('Allow', 'GET, HEAD');
    response.writeHead(405);
    return response.end();
  }

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    response.writeHead(400);
    return response.end('Bad request');
  }

  const relativePath = decodedPath === '/' ? 'Index.html' : decodedPath.replace(/^[/\\]+/, '');
  const resolvedPath = path.resolve(root, relativePath);
  const relativeToRoot = path.relative(root, resolvedPath);

  if (!relativeToRoot || relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot) ||
      relativeToRoot.split(path.sep).some(part => part.startsWith('.')) ||
      ['server.js', 'setup-admin.js', 'package.json', 'package-lock.json', 'README.md', 'admin.html']
        .includes(path.basename(resolvedPath).toLowerCase())) {
    response.writeHead(404);
    return response.end('Not found');
  }

  const contentType = contentTypes.get(path.extname(resolvedPath).toLowerCase());
  if (!contentType) {
    response.writeHead(404);
    return response.end('Not found');
  }

  try {
    const file = await fs.readFile(resolvedPath);
    response.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'X-Frame-Options': 'DENY'
    });
    response.end(request.method === 'HEAD' ? undefined : file);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'EISDIR') {
      response.writeHead(404);
      return response.end('Not found');
    }
    throw error;
  }
}

const server = http.createServer(async (request, response) => {
  let pathname;
  try {
    pathname = new URL(request.url, `http://${request.headers.host || 'localhost'}`).pathname;
  } catch {
    response.writeHead(400);
    return response.end('Bad request');
  }

  if (pathname === '/healthz') {
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      response.writeHead(405);
      return response.end();
    }
    return sendJson(response, 200, {
      status: 'ok',
      privateInboxConfigured: adminConfigured
    });
  }

  if (pathname === '/api/registrations') {
    return sendJson(response, 410, { error: 'Membership applications are not accepted on this website.' });
  }

  if (pathname.startsWith('/api/admin/')) {
    return handleAdminApi(request, response, pathname);
  }

  if (pathname === '/admin' || pathname === '/admin/') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.setHeader('Allow', 'GET, HEAD');
      response.writeHead(405);
      return response.end();
    }
    if (!adminConfigured) return sendPage(response, 503,
      Buffer.from('<!DOCTYPE html><html lang="en"><meta charset="utf-8"><title>Private inbox unavailable</title><p>Private inbox is not configured. Run <code>npm run setup-admin</code> on the server.</p></html>'));
    if (process.env.NODE_ENV === 'production' && !isSecureRequest(request)) {
      return sendPage(response, 426,
        Buffer.from('<!DOCTYPE html><html lang="en"><meta charset="utf-8"><title>HTTPS required</title><p>The private inbox requires HTTPS.</p></html>'));
    }
    return sendAdminPage(response);
  }

  if (pathname.toLowerCase() === '/admin.html' ||
      pathname.toLowerCase().endsWith('/applications.enc')) {
    response.writeHead(404);
    return response.end('Not found');
  }

  try {
    await serveFile(request, response, pathname);
  } catch (error) {
    console.error(`File request failed (${error.code || error.name}).`);
    if (!response.headersSent) response.writeHead(500);
    response.end('Internal server error');
  }
});

server.listen(port, host, () => {
  console.log(`STREAM Club website listening at http://${host}:${port}`);
  console.log(`Private application inbox: ${adminConfigured ? 'configured' : 'not configured'}`);
});

server.on('error', error => {
  console.error(`Could not start the website server (${error.code || error.message}).`);
  process.exitCode = 1;
});
