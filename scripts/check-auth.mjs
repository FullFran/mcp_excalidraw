#!/usr/bin/env node

// Checks for authentication (docs/auth.md): OAuth 2.1 resource server on
// /mcp, the built-in authorization server (DCR, CIMD, PKCE, refresh token
// rotation, RFC 9207 `iss`), GitHub login with an allowlist, and the gate in
// front of the canvas page, REST API and WebSocket.
//
// Real `dist/server.js` processes cover startup rules and the full DCR flow
// on the wire. Client ID Metadata Documents, the SSRF guard, token expiry and
// audience binding are driven in-process through `dist/auth/*.js`, where the
// guard and CA can be injected (the server itself always uses the strict
// public-address guard). A fake GitHub and a fake https CIMD host run on
// random loopback ports. Scratch state lives outside the repository.

import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { mkdtempSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');
const distDir = join(repoRoot, 'dist');
const serverPath = join(distDir, 'server.js');
const runtime = process.env.CANVAS_RUNTIME || process.execPath;
const runtimeName = basename(runtime).toLowerCase();
const runtimeArgs = runtimeName.includes('bun') ? ['run', serverPath] : [serverPath];
const require = (await import('node:module')).createRequire(import.meta.url);
const WebSocket = require('ws');

const MODERN_VERSION = '2026-07-28';
const STARTUP_TIMEOUT_MS = 8000;
const GH_CLIENT_ID = 'gh-test-client';
const GH_CLIENT_SECRET = 'gh-test-secret';
const AUTH_SECRET = randomBytes(36).toString('base64');
const ALLOWED_LOGIN = 'FullFran';

const scratch = mkdtempSync(join(tmpdir(), 'mcp-auth-check-'));
let passed = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message} (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`);
}

function ok(label) {
  passed += 1;
  console.log(`  ok - ${label}`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/** Raw request so Origin/Cookie/Host can be set freely. */
function request(base, { method = 'GET', path = '/', headers = {}, json, form } = {}) {
  const url = new URL(path, base);
  let payload;
  const extra = {};
  if (json !== undefined) {
    payload = JSON.stringify(json);
    extra['content-type'] = 'application/json';
  } else if (form !== undefined) {
    payload = new URLSearchParams(form).toString();
    extra['content-type'] = 'application/x-www-form-urlencoded';
  }
  if (payload !== undefined) extra['content-length'] = Buffer.byteLength(payload);
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers: { ...extra, ...headers } }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => {
        let body;
        try { body = JSON.parse(text); } catch { body = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, body });
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error(`request timed out: ${method} ${path}`)));
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function setCookies(response) {
  const jar = {};
  for (const line of response.headers['set-cookie'] ?? []) {
    const [pair, ...attributes] = line.split(';');
    const index = pair.indexOf('=');
    jar[pair.slice(0, index).trim()] = { value: pair.slice(index + 1).trim(), attributes: attributes.map(a => a.trim()) };
  }
  return jar;
}

function cookieHeader(jar) {
  return Object.entries(jar)
    .filter(([, cookie]) => cookie.value !== '')
    .map(([name, cookie]) => `${name}=${cookie.value}`)
    .join('; ');
}

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ---------------------------------------------------------------------------
// Fake GitHub: codes are `code-<login>`; tokens are `tok-<login>`.
// ---------------------------------------------------------------------------

async function startFakeGitHub() {
  const port = await freePort();
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (req.method === 'POST' && url.pathname === '/login/oauth/access_token') {
        const params = new URLSearchParams(raw);
        res.setHeader('content-type', 'application/json');
        if (params.get('client_id') !== GH_CLIENT_ID || params.get('client_secret') !== GH_CLIENT_SECRET) {
          res.end(JSON.stringify({ error: 'incorrect_client_credentials' }));
          return;
        }
        const code = params.get('code') ?? '';
        if (!code.startsWith('code-')) {
          res.end(JSON.stringify({ error: 'bad_verification_code' }));
          return;
        }
        res.end(JSON.stringify({ access_token: `tok-${code.slice(5)}`, token_type: 'bearer', scope: '' }));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/user') {
        const token = /^Bearer tok-(.+)$/.exec(req.headers.authorization ?? '')?.[1];
        res.setHeader('content-type', 'application/json');
        if (!token) {
          res.statusCode = 401;
          res.end(JSON.stringify({ message: 'Bad credentials' }));
          return;
        }
        res.end(JSON.stringify({ login: token, id: 1 }));
        return;
      }
      res.statusCode = 404;
      res.end('not found');
    });
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

// ---------------------------------------------------------------------------
// OAuth flow driver (works against the real server and the in-process app)
// ---------------------------------------------------------------------------

/** Logs in through the fake GitHub; returns the cookie jar holding the session. */
async function githubLogin(base, githubUrl, login, returnTo = '/') {
  const start = await request(base, { path: `/oauth/login?return_to=${encodeURIComponent(returnTo)}` });
  assertEqual(start.status, 302, 'login redirects to GitHub');
  const location = new URL(start.headers.location);
  assertEqual(location.origin, new URL(githubUrl).origin, 'login goes to the configured GitHub');
  assertEqual(location.searchParams.get('client_id'), GH_CLIENT_ID, 'GitHub client_id');
  assertEqual(location.searchParams.get('redirect_uri'), `${base}/oauth/github/callback`, 'GitHub callback URL');
  const state = location.searchParams.get('state');
  const jar = setCookies(start);
  const callback = await request(base, {
    path: `/oauth/github/callback?code=code-${encodeURIComponent(login)}&state=${encodeURIComponent(state)}`,
    headers: { cookie: cookieHeader(jar) }
  });
  return { callback, jar: { ...jar, ...setCookies(callback) }, state };
}

function sessionCookieName(jar) {
  return Object.keys(jar).find(name => name.endsWith('wb_session') && jar[name].value !== '');
}

/** authorize -> (login) -> consent -> code. Returns the redirect URL carrying code/state/iss. */
async function authorize(base, { clientId, redirectUri, challenge, method = 'S256', state = 'xyz', resource, scope, jar }) {
  const params = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, state });
  if (challenge !== undefined) params.set('code_challenge', challenge);
  if (method !== undefined) params.set('code_challenge_method', method);
  if (resource !== undefined) params.set('resource', resource);
  if (scope !== undefined) params.set('scope', scope);
  const path = `/oauth/authorize?${params}`;
  const first = await request(base, { path, headers: jar ? { cookie: cookieHeader(jar) } : {} });
  return { first, path };
}

async function consent(base, jar, consentPage, decision = 'approve', origin = base) {
  const ticket = /name="ticket" value="([^"]+)"/.exec(consentPage.text)?.[1];
  assert(ticket, `consent page carries a ticket: ${consentPage.text.slice(0, 300)}`);
  return request(base, {
    method: 'POST',
    path: '/oauth/authorize',
    headers: { cookie: cookieHeader(jar), ...(origin ? { origin } : {}) },
    form: { ticket: ticket.replace(/&amp;/g, '&'), decision }
  });
}

/** Full happy path; returns { code, redirect } for the given client. */
async function obtainCode(base, jar, { clientId, redirectUri, challenge, resource }) {
  const { first } = await authorize(base, { clientId, redirectUri, challenge, resource, jar });
  assertEqual(first.status, 200, `consent page (${first.text.slice(0, 200)})`);
  const decided = await consent(base, jar, first);
  assertEqual(decided.status, 303, 'approval redirects');
  const redirect = new URL(decided.headers.location);
  const code = redirect.searchParams.get('code');
  assert(code, `approval redirect carries a code: ${decided.headers.location}`);
  return { code, redirect };
}

function tokenRequest(base, form, headers = {}) {
  return request(base, { method: 'POST', path: '/oauth/token', form, headers });
}

function mcpToolsList(base, accessToken) {
  return request(base, {
    method: 'POST',
    path: '/mcp',
    headers: {
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': MODERN_VERSION,
      'mcp-method': 'tools/list',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {})
    },
    json: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': MODERN_VERSION,
          'io.modelcontextprotocol/clientCapabilities': {},
          'io.modelcontextprotocol/clientInfo': { name: 'auth-test', version: '0.0.0' }
        }
      }
    }
  });
}

function jsonRpcResult(response, id) {
  const contentType = String(response.headers['content-type'] || '');
  const messages = contentType.includes('text/event-stream')
    ? response.text.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => JSON.parse(l.slice(5).trim()))
    : [JSON.parse(response.text)].flat();
  const answer = messages.find(m => m.id === id);
  assert(answer && answer.result, `JSON-RPC result for id ${id}: ${response.text.slice(0, 300)}`);
  return answer.result;
}

function wsConnect(url, headers) {
  return new Promise(resolve => {
    const socket = new WebSocket(url, { headers });
    const timer = setTimeout(() => { socket.terminate(); resolve({ ok: false, status: 'timeout' }); }, 5000);
    socket.once('message', data => {
      clearTimeout(timer);
      socket.close();
      resolve({ ok: true, message: JSON.parse(String(data)) });
    });
    socket.once('unexpected-response', (_req, res) => {
      clearTimeout(timer);
      resolve({ ok: false, status: res.statusCode });
    });
    socket.once('error', error => {
      clearTimeout(timer);
      resolve({ ok: false, status: error.message });
    });
  });
}

// ---------------------------------------------------------------------------
// Real server processes
// ---------------------------------------------------------------------------

function spawnCanvas(port, extraEnv = {}) {
  const env = {
    ...process.env,
    PORT: String(port),
    HOST: '127.0.0.1',
    LOG_LEVEL: 'error',
    LOG_FILE_PATH: join(scratch, `canvas-${port}.log`),
    XDG_STATE_HOME: scratch,
    EXCALIDRAW_NO_AUTOSTART: '1'
  };
  for (const name of [
    'EXPRESS_SERVER_URL', 'PUBLIC_BASE_URL', 'TRUST_PROXY', 'EXCALIDRAW_DATA_DIR', 'AUTH_MODE', 'ALLOW_INSECURE_NO_AUTH',
    'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_CLIENT_SECRET_FILE', 'ALLOWED_GITHUB_LOGINS', 'AUTH_SECRET',
    'AUTH_SECRET_FILE', 'GITHUB_OAUTH_BASE_URL', 'GITHUB_API_BASE_URL'
  ]) delete env[name];
  Object.assign(env, extraEnv);
  const child = spawn(runtime, runtimeArgs, { cwd: scratch, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  child.stderr.on('data', chunk => { output += chunk.toString(); });
  return { child, output: () => output.trim() };
}

async function waitForHealth(baseUrl, canvas) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (canvas.child.exitCode !== null) throw new Error(`canvas exited early with ${canvas.child.exitCode}: ${canvas.output()}`);
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(400) });
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await sleep(100);
  }
  throw new Error(`canvas did not become healthy: ${canvas.output()}`);
}

function waitForExit(child, timeoutMs = STARTUP_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('process did not exit')); }, timeoutMs);
    child.once('exit', code => { clearTimeout(timer); resolve(code); });
  });
}

async function stop(canvas) {
  if (canvas.child.exitCode !== null) return;
  canvas.child.kill('SIGTERM');
  await waitForExit(canvas.child).catch(() => {});
}

async function expectStartupRefusal(label, env, mustMention) {
  const port = await freePort();
  const canvas = spawnCanvas(port, env);
  const code = await waitForExit(canvas.child);
  assert(code !== 0, `${label}: expected a non-zero exit, got ${code}`);
  const log = canvas.output();
  for (const text of mustMention) assert(log.includes(text), `${label}: startup error should mention ${text}: ${log}`);
  ok(label);
}

function authEnv(port, githubUrl, dataDir, extra = {}) {
  return {
    AUTH_MODE: 'oauth',
    PUBLIC_BASE_URL: `http://127.0.0.1:${port}`,
    GITHUB_CLIENT_ID: GH_CLIENT_ID,
    GITHUB_CLIENT_SECRET: GH_CLIENT_SECRET,
    GITHUB_OAUTH_BASE_URL: githubUrl,
    GITHUB_API_BASE_URL: githubUrl,
    ALLOWED_GITHUB_LOGINS: `someone-else, ${ALLOWED_LOGIN.toLowerCase()}`,
    AUTH_SECRET,
    EXCALIDRAW_DATA_DIR: dataDir,
    ...extra
  };
}

async function checkDefaultLoopbackStaysOpen() {
  const port = await freePort();
  const canvas = spawnCanvas(port);
  const base = `http://127.0.0.1:${port}`;
  try {
    await waitForHealth(base, canvas);
    const elements = await request(base, { path: '/api/elements' });
    assertEqual(elements.status, 200, 'GET /api/elements without credentials on default loopback');
    const created = await request(base, { method: 'POST', path: '/api/elements', json: { type: 'rectangle', x: 1, y: 2, width: 3, height: 4 } });
    assertEqual(created.status, 200, 'cross-origin-free POST without credentials on default loopback');
    const health = await request(base, { path: '/health' });
    assert(typeof health.body.elements_count === 'number' && typeof health.body.pid === 'number', 'default /health keeps its full body');
    const mcp = await mcpToolsList(base);
    assertEqual(mcp.status, 200, '/mcp without a token on default loopback');
    const metadata = await request(base, { path: '/.well-known/oauth-protected-resource' });
    assertEqual(metadata.status, 404, 'no OAuth metadata when auth is off');
    const ws = await wsConnect(`ws://127.0.0.1:${port}`, {});
    assert(ws.ok, `WebSocket without credentials on default loopback: ${ws.status}`);
    ok('loopback default stays open (REST, /mcp, WebSocket, /health unchanged; no OAuth endpoints)');
  } finally {
    await stop(canvas);
  }
}

async function checkStartupRules() {
  await expectStartupRefusal('non-loopback bind without auth config refuses to start', { HOST: '0.0.0.0' },
    ['PUBLIC_BASE_URL', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'ALLOWED_GITHUB_LOGINS', 'AUTH_SECRET', 'EXCALIDRAW_DATA_DIR']);
  await expectStartupRefusal('AUTH_MODE=off on a non-loopback bind refuses to start', { HOST: '0.0.0.0', AUTH_MODE: 'off' },
    ['ALLOW_INSECURE_NO_AUTH']);
  await expectStartupRefusal('AUTH_MODE=oauth on loopback names the missing variable', {
    AUTH_MODE: 'oauth', PUBLIC_BASE_URL: 'http://127.0.0.1:1', GITHUB_CLIENT_ID: 'x', GITHUB_CLIENT_SECRET: 'y',
    AUTH_SECRET, EXCALIDRAW_DATA_DIR: join(scratch, 'unused')
  }, ['ALLOWED_GITHUB_LOGINS']);
  await expectStartupRefusal('unknown AUTH_MODE refuses to start', { AUTH_MODE: 'maybe' }, ['AUTH_MODE']);
}

async function checkRealServerFlow(github) {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dataDir = join(scratch, `data-${port}`);
  const canvas = spawnCanvas(port, authEnv(port, github.url, dataDir));
  const issued = [];
  try {
    await waitForHealth(base, canvas);

    // --- Resource server discovery ---
    const anonymous = await mcpToolsList(base);
    assertEqual(anonymous.status, 401, '/mcp without a token');
    assertEqual(anonymous.headers['www-authenticate'],
      `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource", scope="whiteboard"`, 'WWW-Authenticate challenge');
    const prm = await request(base, { path: '/.well-known/oauth-protected-resource' });
    assertEqual(prm.status, 200, 'protected resource metadata');
    assertEqual(prm.body.resource, `${base}/mcp`, 'metadata resource');
    assertEqual(JSON.stringify(prm.body.authorization_servers), JSON.stringify([base]), 'metadata authorization_servers');
    const asm = await request(base, { path: '/.well-known/oauth-authorization-server' });
    assertEqual(asm.body.issuer, base, 'AS issuer');
    assertEqual(JSON.stringify(asm.body.code_challenge_methods_supported), '["S256"]', 'only S256');
    assertEqual(asm.body.authorization_response_iss_parameter_supported, true, 'RFC 9207 advertised');
    assertEqual(asm.body.client_id_metadata_document_supported, true, 'CIMD advertised');
    assertEqual(asm.body.registration_endpoint, `${base}/oauth/register`, 'DCR endpoint');
    ok('401 + WWW-Authenticate resource_metadata on /mcp; RFC 9728 and RFC 8414 metadata');

    // --- /health leaks nothing ---
    const health = await request(base, { path: '/health' });
    assertEqual(JSON.stringify(Object.keys(health.body).sort()), '["service","status"]', '/health body with auth on');
    ok('/health stays open and only reports status + service');

    // --- DCR ---
    for (const bad of ['myapp://callback', 'http://evil.example/callback', 'https://x.example/cb#frag']) {
      const rejected = await request(base, { method: 'POST', path: '/oauth/register', json: { redirect_uris: [bad] } });
      assertEqual(rejected.status, 400, `DCR rejects redirect ${bad}`);
    }
    const redirectUri = 'http://127.0.0.1:43123/callback';
    const registration = await request(base, {
      method: 'POST', path: '/oauth/register',
      json: { client_name: 'Test CLI', redirect_uris: [redirectUri, 'https://chatgpt.com/connector_platform_oauth_redirect'], token_endpoint_auth_method: 'none' }
    });
    assertEqual(registration.status, 201, `DCR registration (${registration.text})`);
    const clientId = registration.body.client_id;
    ok('DCR registers public clients; rejects custom-scheme, non-loopback http and fragment redirects');

    // --- authorize without session -> login ---
    const { challenge, verifier } = pkcePair();
    const { first, path: authorizePath } = await authorize(base, { clientId, redirectUri, challenge });
    assertEqual(first.status, 302, 'authorize without a session redirects');
    assertEqual(first.headers.location, `/oauth/login?return_to=${encodeURIComponent(authorizePath)}`, 'redirect to login keeps the request');

    // Disallowed GitHub account gets no session.
    const mallory = await githubLogin(base, github.url, 'mallory', authorizePath);
    assertEqual(mallory.callback.status, 403, 'disallowed GitHub login');
    assert(!sessionCookieName(mallory.jar), 'disallowed login sets no session cookie');
    // Forged/missing state gets no session.
    const forged = await request(base, { path: '/oauth/github/callback?code=code-FullFran&state=forged' });
    assertEqual(forged.status, 400, 'callback without the state cookie');
    assert(!sessionCookieName(setCookies(forged)), 'forged callback sets no session cookie');
    ok('disallowed GitHub login and forged state get no session');

    const login = await githubLogin(base, github.url, ALLOWED_LOGIN, authorizePath);
    assertEqual(login.callback.status, 302, 'allowed login redirects back');
    assertEqual(login.callback.headers.location, authorizePath, 'login returns to the authorize request');
    const sessionName = sessionCookieName(login.jar);
    assert(sessionName, 'allowed login sets a session cookie');
    const attributes = login.jar[sessionName].attributes;
    for (const attribute of ['HttpOnly', 'SameSite=Lax', 'Path=/']) assert(attributes.includes(attribute), `session cookie has ${attribute}`);
    assert(attributes.some(a => a.startsWith('Max-Age=')), 'session cookie expires');
    const jar = { [sessionName]: login.jar[sessionName] };
    ok('allowed GitHub login (case-insensitive) gets an HttpOnly SameSite=Lax expiring session');

    // --- consent ---
    const consentPage = await request(base, { path: authorizePath, headers: { cookie: cookieHeader(jar) } });
    assertEqual(consentPage.status, 200, 'consent page');
    assert(consentPage.text.includes('Test CLI') && consentPage.text.includes(clientId) && consentPage.text.includes('127.0.0.1:43123'),
      'consent page shows client name, id and redirect host');
    assertEqual(consentPage.headers['x-frame-options'], 'DENY', 'consent page cannot be framed');
    const evilConsent = await consent(base, jar, consentPage, 'approve', 'https://evil.example');
    assertEqual(evilConsent.status, 403, 'consent POST from another origin');
    const noOriginConsent = await consent(base, jar, consentPage, 'approve', null);
    assertEqual(noOriginConsent.status, 403, 'consent POST without Origin');
    const denied = await consent(base, jar, consentPage, 'deny');
    const deniedUrl = new URL(denied.headers.location);
    assertEqual(deniedUrl.searchParams.get('error'), 'access_denied', 'deny returns access_denied');
    assertEqual(deniedUrl.searchParams.get('iss'), base, 'deny carries iss');
    const approved = await consent(base, jar, consentPage);
    assertEqual(approved.status, 303, 'approve redirects');
    const approvedUrl = new URL(approved.headers.location);
    assertEqual(`${approvedUrl.origin}${approvedUrl.pathname}`, redirectUri, 'code goes to the registered redirect');
    assertEqual(approvedUrl.searchParams.get('state'), 'xyz', 'state echoed');
    assertEqual(approvedUrl.searchParams.get('iss'), base, 'RFC 9207 iss in the redirect');
    const code = approvedUrl.searchParams.get('code');
    ok('consent page (client, id, redirect host); cross-origin consent rejected; iss + state in redirects');

    // --- token exchange ---
    const exchange = await tokenRequest(base, {
      grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource: `${base}/mcp`
    });
    assertEqual(exchange.status, 200, `token exchange (${exchange.text})`);
    assertEqual(exchange.headers['cache-control'], 'no-store', 'token response not cacheable');
    assertEqual(exchange.body.token_type, 'Bearer', 'token type');
    assert(exchange.body.expires_in === 3600, 'access token lives 1 h by default');
    issued.push(exchange.body.access_token, exchange.body.refresh_token);
    const tools = await mcpToolsList(base, exchange.body.access_token);
    const toolList = jsonRpcResult(tools, 1).tools;
    assert(Array.isArray(toolList) && toolList.length > 0, '/mcp tools/list with the bearer');
    ok('DCR -> authorize -> GitHub -> consent -> code -> token (PKCE) -> /mcp tools/list');

    // Reused code: rejected, and what it issued is revoked.
    const reuse = await tokenRequest(base, {
      grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier
    });
    assertEqual(reuse.body?.error, 'invalid_grant', 'reused code');
    assertEqual((await mcpToolsList(base, exchange.body.access_token)).status, 401, 'tokens from a replayed code are revoked');
    ok('reused authorization code rejected and its tokens revoked');

    // Wrong PKCE verifier (and the code is burnt afterwards).
    {
      const pair = pkcePair();
      const { code: c } = await obtainCode(base, jar, { clientId, redirectUri, challenge: pair.challenge });
      const wrong = await tokenRequest(base, { grant_type: 'authorization_code', code: c, redirect_uri: redirectUri, client_id: clientId, code_verifier: pkcePair().verifier });
      assertEqual(wrong.body?.error, 'invalid_grant', 'wrong PKCE verifier');
      const retry = await tokenRequest(base, { grant_type: 'authorization_code', code: c, redirect_uri: redirectUri, client_id: clientId, code_verifier: pair.verifier });
      assertEqual(retry.body?.error, 'invalid_grant', 'code burnt after a failed attempt');
    }
    // Wrong redirect_uri at the token endpoint.
    {
      const pair = pkcePair();
      const { code: c } = await obtainCode(base, jar, { clientId, redirectUri, challenge: pair.challenge });
      const wrong = await tokenRequest(base, { grant_type: 'authorization_code', code: c, redirect_uri: 'http://127.0.0.1:43123/other', client_id: clientId, code_verifier: pair.verifier });
      assertEqual(wrong.body?.error, 'invalid_grant', 'wrong redirect_uri at token');
    }
    // Wrong resource at the token endpoint.
    {
      const pair = pkcePair();
      const { code: c } = await obtainCode(base, jar, { clientId, redirectUri, challenge: pair.challenge });
      const wrong = await tokenRequest(base, { grant_type: 'authorization_code', code: c, redirect_uri: redirectUri, client_id: clientId, code_verifier: pair.verifier, resource: 'https://other.example/mcp' });
      assertEqual(wrong.body?.error, 'invalid_target', 'wrong resource at token');
    }
    ok('wrong PKCE verifier, wrong redirect_uri and wrong resource rejected at the token endpoint');

    // --- authorize-time rejections ---
    {
      const unregistered = await authorize(base, { clientId, redirectUri: 'http://127.0.0.1:43123/elsewhere', challenge, jar });
      assertEqual(unregistered.first.status, 400, 'unregistered redirect_uri');
      assert(!unregistered.first.headers.location, 'no redirect to an unregistered URI');
      const unknownClient = await authorize(base, { clientId: 'dcr_unknown', redirectUri, challenge, jar });
      assertEqual(unknownClient.first.status, 400, 'unknown client');
      const expectRedirectError = async (label, options, error) => {
        const { first: response } = await authorize(base, { clientId, redirectUri, jar, ...options });
        assertEqual(response.status, 302, `${label}: redirect`);
        const url = new URL(response.headers.location);
        assertEqual(url.searchParams.get('error'), error, label);
        assertEqual(url.searchParams.get('iss'), base, `${label}: iss`);
      };
      await expectRedirectError('plain PKCE', { challenge, method: 'plain' }, 'invalid_request');
      await expectRedirectError('missing PKCE', { challenge: undefined, method: undefined }, 'invalid_request');
      await expectRedirectError('wrong resource', { challenge, resource: 'https://other.example/mcp' }, 'invalid_target');
      await expectRedirectError('unknown scope', { challenge, scope: 'admin' }, 'invalid_scope');
    }
    ok('authorize rejects unregistered redirects (no redirect), unknown clients, plain/missing PKCE, wrong resource, unknown scope');

    // --- refresh rotation ---
    const pair = pkcePair();
    const { code: freshCode } = await obtainCode(base, jar, { clientId, redirectUri, challenge: pair.challenge, resource: `${base}/mcp` });
    const tokens = (await tokenRequest(base, { grant_type: 'authorization_code', code: freshCode, redirect_uri: redirectUri, client_id: clientId, code_verifier: pair.verifier })).body;
    issued.push(tokens.access_token, tokens.refresh_token);
    const rotated = await tokenRequest(base, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });
    assertEqual(rotated.status, 200, `refresh (${rotated.text})`);
    assert(rotated.body.refresh_token !== tokens.refresh_token, 'refresh token rotates');
    issued.push(rotated.body.access_token, rotated.body.refresh_token);
    assertEqual((await mcpToolsList(base, rotated.body.access_token)).status, 200, 'rotated access token works');
    const replay = await tokenRequest(base, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });
    assertEqual(replay.body?.error, 'invalid_grant', 'old refresh token reuse');
    const afterRevoke = await tokenRequest(base, { grant_type: 'refresh_token', refresh_token: rotated.body.refresh_token, client_id: clientId });
    assertEqual(afterRevoke.body?.error, 'invalid_grant', 'reuse revoked the newest refresh token too');
    assertEqual((await mcpToolsList(base, rotated.body.access_token)).status, 401, 'reuse revoked the family access token');
    const otherClient = await request(base, { method: 'POST', path: '/oauth/register', json: { redirect_uris: [redirectUri] } });
    const crossClient = await tokenRequest(base, { grant_type: 'refresh_token', refresh_token: rotated.body.refresh_token, client_id: otherClient.body.client_id });
    assertEqual(crossClient.body?.error, 'invalid_grant', 'refresh token bound to its client');
    ok('refresh tokens rotate; reuse of an old one revokes the whole family');

    // --- canvas, REST API and WebSocket ---
    const pair2 = pkcePair();
    const { code: apiCode } = await obtainCode(base, jar, { clientId, redirectUri, challenge: pair2.challenge });
    const apiTokens = (await tokenRequest(base, { grant_type: 'authorization_code', code: apiCode, redirect_uri: redirectUri, client_id: clientId, code_verifier: pair2.verifier })).body;
    issued.push(apiTokens.access_token, apiTokens.refresh_token);
    const bearer = { authorization: `Bearer ${apiTokens.access_token}` };
    const cookie = { cookie: cookieHeader(jar) };

    const page = await request(base, { path: '/' });
    assertEqual(page.status, 302, 'canvas page without a session');
    assert(page.headers.location.startsWith('/oauth/login?return_to='), 'canvas page redirects to login');
    const asset = await request(base, { path: '/server.js' });
    assertEqual(asset.status, 302, 'static files without a session');
    const pageWithSession = await request(base, { path: '/', headers: cookie });
    assert(pageWithSession.status === 200 || pageWithSession.status === 404, `canvas page with a session is served (got ${pageWithSession.status})`);

    assertEqual((await request(base, { path: '/api/elements' })).status, 401, '/api/elements without credentials');
    assertEqual((await request(base, { path: '/api/elements', headers: { authorization: 'Bearer nope' } })).status, 401, '/api/elements with a bad token');
    assertEqual((await request(base, { path: '/api/elements', headers: bearer })).status, 200, '/api/elements with a bearer');
    assertEqual((await request(base, { path: '/api/elements', headers: cookie })).status, 200, '/api/elements with the session cookie');
    const element = { type: 'rectangle', x: 10, y: 20, width: 30, height: 40 };
    assertEqual((await request(base, { method: 'POST', path: '/api/elements', json: element })).status, 401, 'POST without credentials');
    assertEqual((await request(base, { method: 'POST', path: '/api/elements', json: element, headers: { ...cookie, origin: 'https://evil.example' } })).status, 403, 'cookie POST from another origin');
    assertEqual((await request(base, { method: 'POST', path: '/api/elements', json: element, headers: cookie })).status, 403, 'cookie POST without Origin');
    assertEqual((await request(base, { method: 'POST', path: '/api/elements', json: element, headers: { ...cookie, origin: base } })).status, 200, 'cookie POST from our origin');
    assertEqual((await request(base, { method: 'POST', path: '/api/elements', json: element, headers: bearer })).status, 200, 'bearer POST without Origin');
    ok('canvas page and static assets need a session; /api accepts cookie or bearer; cookie writes need our Origin');

    // MCP tool calls still reach the gated REST API in-process.
    const call = await request(base, {
      method: 'POST', path: '/mcp',
      headers: { ...bearer, accept: 'application/json, text/event-stream', 'mcp-protocol-version': MODERN_VERSION, 'mcp-method': 'tools/call', 'mcp-name': 'create_element' },
      json: {
        jsonrpc: '2.0', id: 7, method: 'tools/call',
        params: {
          name: 'create_element',
          arguments: { id: 'auth-check-element', type: 'rectangle', x: 0, y: 0, width: 50, height: 50 },
          _meta: {
            'io.modelcontextprotocol/protocolVersion': MODERN_VERSION,
            'io.modelcontextprotocol/clientCapabilities': {},
            'io.modelcontextprotocol/clientInfo': { name: 'auth-test', version: '0.0.0' }
          }
        }
      }
    });
    const callResult = jsonRpcResult(call, 7);
    assert(!callResult.isError, `create_element over /mcp: ${JSON.stringify(callResult).slice(0, 300)}`);
    const created = await request(base, { path: '/api/elements/auth-check-element', headers: bearer });
    assertEqual(created.status, 200, 'element created through /mcp is in the canvas');
    ok('MCP tools over /mcp still reach the gated REST API (in-process credential)');

    const wsUrl = `ws://127.0.0.1:${port}`;
    const wsNone = await wsConnect(wsUrl, {});
    assertEqual(wsNone.status, 401, 'WebSocket without credentials');
    const wsBearer = await wsConnect(wsUrl, bearer);
    assert(wsBearer.ok && wsBearer.message.type === 'initial_elements', `WebSocket with a bearer: ${wsBearer.status}`);
    const wsCookie = await wsConnect(wsUrl, { ...cookie, origin: base });
    assert(wsCookie.ok, `WebSocket with the session cookie and our Origin: ${wsCookie.status}`);
    const wsEvil = await wsConnect(wsUrl, { ...cookie, origin: 'https://evil.example' });
    assertEqual(wsEvil.status, 403, 'WebSocket with the cookie from another origin');
    const wsNoOrigin = await wsConnect(wsUrl, cookie);
    assertEqual(wsNoOrigin.status, 403, 'WebSocket with the cookie and no Origin');
    ok('WebSocket needs a bearer or the session cookie with our Origin');

    // --- store holds hashes only ---
    const storePath = join(dataDir, 'auth-store.json');
    const stored = readFileSync(storePath, 'utf8');
    for (const token of issued) assert(!stored.includes(token), 'raw token found in the auth store');
    // Revoked access tokens are deleted; the live pair must be there, hashed.
    for (const token of [apiTokens.access_token, apiTokens.refresh_token]) {
      assert(stored.includes(createHash('sha256').update(token).digest('hex')), 'live token hash present in the store');
    }
    assertEqual(statSync(storePath).mode & 0o777, 0o600, 'auth store file mode');
    ok('auth store holds only SHA-256 hashes, mode 0600');

    // --- logout ---
    const logout = await request(base, { method: 'POST', path: '/oauth/logout', headers: { ...cookie, origin: base } });
    assertEqual(logout.status, 303, 'logout');
    assert(Object.values(setCookies(logout)).some(c => c.value === '' && c.attributes.includes('Max-Age=0')), 'logout clears the cookie');
    ok('logout clears the session cookie');
  } catch (error) {
    error.message += `\n--- canvas output ---\n${canvas.output()}`;
    throw error;
  } finally {
    await stop(canvas);
  }
}

// ---------------------------------------------------------------------------
// In-process checks
// ---------------------------------------------------------------------------

function makeCertificate() {
  const dir = join(scratch, 'tls');
  mkdirSync(dir, { recursive: true });
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  ], { stdio: 'ignore' });
  return { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) };
}

async function startCimdHost(tls) {
  const port = await freePort();
  const documents = new Map();
  const server = https.createServer(tls, (req, res) => {
    const document = documents.get(req.url);
    if (!document) {
      res.statusCode = 404;
      res.end('{}');
      return;
    }
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'max-age=60');
    res.end(JSON.stringify(document(port)));
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  // `localhost` may resolve to ::1 first: answer there too when IPv6 exists.
  const server6 = https.createServer(tls, server.listeners('request')[0]);
  const has6 = await new Promise(resolve => {
    server6.once('error', () => resolve(false));
    server6.listen(port, '::1', () => resolve(true));
  });
  const close = async () => {
    await new Promise(resolve => server.close(resolve));
    if (has6) await new Promise(resolve => server6.close(resolve));
  };
  return { port, documents, close };
}

async function startInProcessApp(auth) {
  const express = (await import(pathToFileURL(join(repoRoot, 'node_modules', 'express', 'index.js')).href)).default;
  const app = express();
  app.use(auth.router);
  app.post('/mcp', auth.mcpBearer, (_req, res) => res.json({ ok: true, login: res.locals.mcpAuthInfo.extra.login, resource: String(res.locals.mcpAuthInfo.resource) }));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

async function checkInProcess(github) {
  const authModule = await import(pathToFileURL(join(distDir, 'auth', 'index.js')).href);
  const ssrf = await import(pathToFileURL(join(distDir, 'auth', 'ssrf.js')).href);
  const clients = await import(pathToFileURL(join(distDir, 'auth', 'clients.js')).href);
  const { createAuth, resolveAuthConfig, AuthConfigError } = authModule;

  // --- config rules ---
  assertEqual(resolveAuthConfig('127.0.0.1', {}).mode, 'off', 'loopback default');
  assertEqual(resolveAuthConfig('localhost', { GITHUB_CLIENT_ID: 'x' }).mode, 'off', 'loopback ignores stray GitHub vars without AUTH_MODE');
  const insecure = resolveAuthConfig('0.0.0.0', { AUTH_MODE: 'off', ALLOW_INSECURE_NO_AUTH: 'true' });
  assert(insecure.mode === 'off' && insecure.insecure === true, 'ALLOW_INSECURE_NO_AUTH=true allows auth off on a public bind');
  const fullEnv = {
    PUBLIC_BASE_URL: 'https://board.example.com', GITHUB_CLIENT_ID: 'id', GITHUB_CLIENT_SECRET: 'secret',
    ALLOWED_GITHUB_LOGINS: 'FullFran', AUTH_SECRET, EXCALIDRAW_DATA_DIR: join(scratch, 'cfg')
  };
  const onConfig = resolveAuthConfig('0.0.0.0', fullEnv);
  assert(onConfig.mode === 'oauth' && onConfig.resource === 'https://board.example.com/mcp' && onConfig.secureCookies, 'public bind with full config');
  const throwsWith = (env, text, label) => {
    try {
      resolveAuthConfig('0.0.0.0', env);
    } catch (error) {
      assert(error instanceof AuthConfigError && error.message.includes(text), `${label}: ${error.message}`);
      return;
    }
    throw new Error(`${label}: expected a configuration error`);
  };
  throwsWith({ ...fullEnv, PUBLIC_BASE_URL: 'http://board.example.com' }, 'https', 'http public base URL');
  throwsWith({ ...fullEnv, PUBLIC_BASE_URL: 'https://board.example.com/sub' }, 'without a path', 'base URL with a path');
  throwsWith({ ...fullEnv, AUTH_SECRET: 'short' }, 'AUTH_SECRET', 'short secret');
  throwsWith({ ...fullEnv, ALLOWED_GITHUB_LOGINS: 'bad login!' }, 'invalid GitHub login', 'bad login');
  ok('config: loopback default off, ALLOW_INSECURE_NO_AUTH, https/origin-only base URL, secret length, login syntax');

  // --- SSRF guard (the strict default, as the server uses it) ---
  const { publicAddressGuard, safeFetch } = ssrf;
  for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '::1', '::', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '224.0.0.1']) {
    assert(!publicAddressGuard(address), `guard blocks ${address}`);
  }
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert(publicAddressGuard(address), `guard allows ${address}`);

  const tls = makeCertificate();
  const cimdHost = await startCimdHost(tls);
  const cimdBase = `https://localhost:${cimdHost.port}`;
  for (const url of [`https://127.0.0.1:${cimdHost.port}/client.json`, `${cimdBase}/client.json`, `https://[::1]:${cimdHost.port}/client.json`]) {
    let blocked = false;
    try {
      await safeFetch(url, { ca: tls.cert });
    } catch (error) {
      blocked = error.name === 'SafeFetchError' && /non-public/.test(error.message);
    }
    assert(blocked, `strict guard blocks ${url}`);
  }
  let httpBlocked = false;
  try { await safeFetch(`http://example.com/client.json`); } catch (error) { httpBlocked = /only https/.test(error.message); }
  assert(httpBlocked, 'safeFetch refuses http');
  assert(!clients.isCimdClientId(`http://localhost:${cimdHost.port}/client.json`), 'http client_id is not a CIMD URL');
  assert(!clients.isCimdClientId('https://example.com'), 'CIMD client_id needs a path');
  const strictResolver = new clients.CimdResolver();
  let strictRejected = false;
  try { await strictResolver.resolve(`${cimdBase}/client.json`); } catch (error) { strictRejected = error.code === 'invalid_client'; }
  assert(strictRejected, 'default CIMD resolver refuses a loopback metadata URL');
  ok('SSRF guard: private/loopback/link-local/mapped addresses blocked, https only, loopback CIMD URL refused in non-test mode');

  // --- CIMD flow on an in-process authorization server ---
  const loopbackOnly = address => address === '127.0.0.1' || address === '::1';
  const goodId = `${cimdBase}/client.json`;
  const mismatchId = `${cimdBase}/mismatch.json`;
  cimdHost.documents.set('/client.json', () => ({
    client_id: goodId, client_name: 'CIMD Agent', redirect_uris: ['http://127.0.0.1/cb', 'https://app.example/cb'],
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none'
  }));
  cimdHost.documents.set('/mismatch.json', () => ({ client_id: 'https://someone-else.example/client.json', redirect_uris: ['https://app.example/cb'] }));

  const storeDir = join(scratch, 'inprocess');
  const makeConfig = (issuerPort, overrides = {}) => ({
    mode: 'oauth',
    issuer: `http://127.0.0.1:${issuerPort}`,
    resource: `http://127.0.0.1:${issuerPort}/mcp`,
    secureCookies: false,
    github: { clientId: GH_CLIENT_ID, clientSecret: GH_CLIENT_SECRET, oauthBaseUrl: github.url, apiBaseUrl: github.url },
    allowedLogins: new Set([ALLOWED_LOGIN.toLowerCase()]),
    secret: Buffer.from(AUTH_SECRET),
    storePath: join(storeDir, 'auth-store.json'),
    accessTokenTtlSeconds: 1,
    refreshTokenTtlSeconds: 3600,
    sessionTtlSeconds: 3600,
    authorizationCodeTtlSeconds: 60,
    ...overrides
  });
  // Injected for tests only: allow the loopback CIMD host and trust its
  // self-signed certificate. https-only and the size/time limits still apply.
  const cimdFetch = { addressGuard: loopbackOnly, ca: tls.cert };
  const realPort = await freePort();
  const configA = makeConfig(realPort);
  const auth = createAuth(configA, { cimdFetch });
  const express = (await import(pathToFileURL(join(repoRoot, 'node_modules', 'express', 'index.js')).href)).default;
  const app = express();
  app.use(auth.router);
  app.post('/mcp', auth.mcpBearer, (_req, res) => res.json({ ok: true, login: res.locals.mcpAuthInfo.extra.login }));
  const server = http.createServer(app);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(realPort, '127.0.0.1', resolve); });
  const base = `http://127.0.0.1:${realPort}`;
  try {
    const login = await githubLogin(base, github.url, ALLOWED_LOGIN);
    const name = sessionCookieName(login.jar);
    const jar = { [name]: login.jar[name] };

    // Loopback redirect with an ephemeral port matches the port-less registration (RFC 8252).
    const redirectUri = 'http://127.0.0.1:51234/cb';
    const pair = pkcePair();
    const { first } = await authorize(base, { clientId: goodId, redirectUri, challenge: pair.challenge, jar });
    assertEqual(first.status, 200, `CIMD consent page (${/<p>([^<]*)<\/p>/.exec(first.text)?.[1]})`);
    assert(first.text.includes('CIMD Agent') && first.text.includes(`localhost:${cimdHost.port}`), 'consent names the CIMD client and its host');
    const decided = await consent(base, jar, first);
    const redirect = new URL(decided.headers.location);
    assertEqual(redirect.searchParams.get('iss'), base, 'CIMD redirect carries iss');
    const tokens = await tokenRequest(base, {
      grant_type: 'authorization_code', code: redirect.searchParams.get('code'), redirect_uri: redirectUri, client_id: goodId, code_verifier: pair.verifier
    });
    assertEqual(tokens.status, 200, `CIMD token exchange (${tokens.text})`);
    const call = await request(base, { method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${tokens.body.access_token}` }, json: {} });
    assertEqual(call.status, 200, 'CIMD access token accepted');
    assertEqual(call.body.login, ALLOWED_LOGIN, 'authInfo carries the GitHub login');

    const notListed = await authorize(base, { clientId: goodId, redirectUri: 'https://evil.example/cb', challenge: pair.challenge, jar });
    assertEqual(notListed.first.status, 400, 'CIMD redirect not in the document');
    assert(!notListed.first.headers.location, 'no redirect for a CIMD redirect not in the document');
    const mismatch = await authorize(base, { clientId: mismatchId, redirectUri: 'https://app.example/cb', challenge: pair.challenge, jar });
    assertEqual(mismatch.first.status, 400, 'CIMD document with another client_id');
    const missing = await authorize(base, { clientId: `${cimdBase}/missing.json`, redirectUri: 'https://app.example/cb', challenge: pair.challenge, jar });
    assertEqual(missing.first.status, 400, 'CIMD document that does not exist');
    ok('CIMD client works (loopback port may vary); redirect not in its document, mismatched client_id, missing document rejected');

    // Expired access token.
    await sleep(1300);
    const expired = await request(base, { method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${tokens.body.access_token}` }, json: {} });
    assertEqual(expired.status, 401, 'expired access token');
    assert(/error="invalid_token"/.test(expired.headers['www-authenticate'] ?? ''), 'expired token challenge says invalid_token');
    ok('expired access token rejected with invalid_token');

    // Audience: a token minted for this resource is refused by another resource sharing the store.
    const fresh = pkcePair();
    const { first: again } = await authorize(base, { clientId: goodId, redirectUri, challenge: fresh.challenge, jar });
    const code = new URL((await consent(base, jar, again)).headers.location).searchParams.get('code');
    const minted = await tokenRequest(base, { grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: goodId, code_verifier: fresh.verifier });
    assertEqual(minted.status, 200, 'second CIMD token');
    // Both instances load the shared store after the token was minted; the
    // positive control proves the token itself is still valid.
    const same = await startInProcessApp(createAuth(configA));
    const other = createAuth({ ...configA, issuer: 'http://127.0.0.1:1', resource: 'http://127.0.0.1:1/mcp' });
    const otherApp = await startInProcessApp(other);
    try {
      const control = await request(same.base, { method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${minted.body.access_token}` }, json: {} });
      assertEqual(control.status, 200, 'positive control: same resource accepts the token');
      const wrongAudience = await request(otherApp.base, { method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${minted.body.access_token}` }, json: {} });
      assertEqual(wrongAudience.status, 401, 'token for another resource rejected');
    } finally {
      await otherApp.close();
      await same.close();
    }
    ok('access token audience-bound to its resource');

    // Rate limit on registration.
    let limited = false;
    for (let i = 0; i < 12; i += 1) {
      const response = await request(base, { method: 'POST', path: '/oauth/register', json: { redirect_uris: ['https://app.example/cb'] } });
      if (response.status === 429) { limited = true; break; }
    }
    assert(limited, '/oauth/register is rate limited');
    ok('/oauth/register rate limited in memory');
  } finally {
    await new Promise(resolve => server.close(resolve));
    await cimdHost.close();
  }
}

// ---------------------------------------------------------------------------

const github = await startFakeGitHub();
try {
  console.log(`Auth checks (scratch: ${scratch})`);
  await checkDefaultLoopbackStaysOpen();
  await checkStartupRules();
  await checkRealServerFlow(github);
  await checkInProcess(github);
  console.log(`Auth check passed: ${passed} groups using ${runtimeName}.`);
} catch (error) {
  console.error(`Auth check failed after ${passed} passing groups: ${error.stack || error.message}`);
  process.exitCode = 1;
} finally {
  await github.close();
}
