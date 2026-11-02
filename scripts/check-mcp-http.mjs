#!/usr/bin/env node

// Wire-level checks for the Streamable HTTP MCP endpoint (`/mcp`) served by
// the canvas server. Every case drives a real `dist/server.js` process with
// hand-written HTTP requests, so what is asserted is exactly what a remote
// client sees on the wire. Both protocol eras are covered:
//   - 2025-11-25 clients: initialize -> notifications/initialized -> requests
//   - 2026-07-28 clients: stateless requests carrying the `_meta` envelope and
//     the Mcp-Method / Mcp-Name / MCP-Protocol-Version headers
// Elements created over MCP must land in the same canvas state the REST API
// serves, because both live in the same process.

import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');
const serverPath = join(repoRoot, 'dist', 'server.js');
const runtime = process.env.CANVAS_RUNTIME || process.execPath;
const runtimeName = basename(runtime).toLowerCase();
const runtimeArgs = runtimeName.includes('bun') ? ['run', serverPath] : [serverPath];

const MODERN_VERSION = '2026-07-28';
const LEGACY_VERSION = '2025-11-25';
const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion';
const CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities';
const CLIENT_INFO_META_KEY = 'io.modelcontextprotocol/clientInfo';
const SERVER_INFO_META_KEY = 'io.modelcontextprotocol/serverInfo';
const HEADER_MISMATCH_CODE = -32020;
const STARTUP_TIMEOUT_MS = 8000;
const PUBLIC_HOST = 'board.example.test';

// Scratch state (logs, pidfiles) lives outside the repository.
const scratch = mkdtempSync(join(tmpdir(), 'mcp-http-check-'));

// Every spawned canvas is tracked and killed when this script exits, even
// when a check throws, so a failing run never leaks a dist/server.js.
const spawned = new Set();
function killAll() {
  for (const child of spawned) {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}
process.on('exit', killAll);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message} (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`);
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

function spawnCanvas(port, extraEnv = {}) {
  const env = {
    ...process.env,
    PORT: String(port),
    HOST: '127.0.0.1',
    LOG_LEVEL: 'error',
    LOG_FILE_PATH: join(scratch, `canvas-${port}.log`),
    XDG_STATE_HOME: scratch,
    EXCALIDRAW_NO_AUTOSTART: '1',
    ...extraEnv
  };
  // The MCP tools must reach the canvas they are mounted on without being
  // told where it is: an inherited EXPRESS_SERVER_URL would mask that.
  delete env.EXPRESS_SERVER_URL;
  delete env.PUBLIC_BASE_URL;
  delete env.TRUST_PROXY;
  delete env.EXCALIDRAW_DATA_DIR;
  Object.assign(env, extraEnv);

  const child = spawn(runtime, runtimeArgs, { cwd: scratch, env, stdio: ['ignore', 'pipe', 'pipe'] });
  spawned.add(child);
  child.once('exit', () => spawned.delete(child));
  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  child.stderr.on('data', chunk => { output += chunk.toString(); });
  return { child, output: () => output.trim() };
}

async function waitForHealth(baseUrl, canvas) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (canvas.child.exitCode !== null) {
      throw new Error(`canvas exited early with ${canvas.child.exitCode}: ${canvas.output()}`);
    }
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(400) });
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`canvas did not become healthy within ${STARTUP_TIMEOUT_MS}ms: ${canvas.output()}`);
}

function waitForExit(child, timeoutMs = STARTUP_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('process did not exit')); }, timeoutMs);
    child.once('exit', code => { clearTimeout(timer); resolve(code); });
  });
}

/**
 * Raw HTTP request through node:http so `Host` and `Origin` can be set
 * freely (fetch forbids overriding Host).
 */
function rawRequest(port, { method = 'POST', path = '/mcp', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        ...(payload !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        accept: 'application/json, text/event-stream',
        ...headers
      }
    }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error('request timed out')));
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

// A Streamable HTTP answer is either one JSON body or an SSE stream whose
// `data:` frames carry JSON-RPC messages. Return the message answering `id`.
function jsonRpcAnswer(response, id, label) {
  const contentType = String(response.headers['content-type'] || '');
  let messages;
  if (contentType.includes('text/event-stream')) {
    messages = response.text
      .split(/\r?\n/)
      .filter(line => line.startsWith('data:'))
      .map(line => line.slice(5).trim())
      .filter(Boolean)
      .map(data => JSON.parse(data));
  } else if (contentType.includes('application/json')) {
    const parsed = JSON.parse(response.text);
    messages = Array.isArray(parsed) ? parsed : [parsed];
  } else {
    throw new Error(`${label}: unexpected content-type ${JSON.stringify(contentType)} (status ${response.status}): ${response.text}`);
  }
  const answer = messages.find(message => message.id === id);
  assert(answer !== undefined, `${label}: no JSON-RPC answer with id ${id} in ${response.text}`);
  return answer;
}

function resultOf(response, id, label) {
  assertEqual(response.status, 200, `${label}: HTTP status`);
  const answer = jsonRpcAnswer(response, id, label);
  assert(answer.error === undefined, `${label}: unexpected error ${JSON.stringify(answer.error)}`);
  assert(answer.result !== undefined, `${label}: answer carried no result`);
  return answer.result;
}

function envelope() {
  return {
    [PROTOCOL_VERSION_META_KEY]: MODERN_VERSION,
    [CLIENT_CAPABILITIES_META_KEY]: {},
    [CLIENT_INFO_META_KEY]: { name: 'excalidraw-http-test', version: '0.0.0' }
  };
}

function modernHeaders(method, name) {
  return {
    'mcp-protocol-version': MODERN_VERSION,
    'mcp-method': method,
    ...(name !== undefined ? { 'mcp-name': name } : {})
  };
}

async function restElement(baseUrl, id) {
  const response = await fetch(`${baseUrl}/api/elements/${encodeURIComponent(id)}`);
  const data = await response.json().catch(() => null);
  return { status: response.status, element: data?.element };
}

async function checkLegacyEra({ port, baseUrl }) {
  const init = await rawRequest(port, {
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: LEGACY_VERSION,
        capabilities: {},
        clientInfo: { name: 'excalidraw-http-test', version: '0.0.0' }
      }
    }
  });
  const initResult = resultOf(init, 1, 'initialize');
  assertEqual(initResult.protocolVersion, LEGACY_VERSION, 'initialize: negotiated protocol version');
  assertEqual(initResult.serverInfo?.name, 'mcp-excalidraw-server', 'initialize: serverInfo.name');
  assert(initResult.capabilities?.tools !== undefined, 'initialize: tools capability must be advertised');

  // A stateless server issues no session id; echo it if one ever appears.
  const sessionId = init.headers['mcp-session-id'];
  const legacyHeaders = {
    'mcp-protocol-version': LEGACY_VERSION,
    ...(sessionId ? { 'mcp-session-id': sessionId } : {})
  };

  const initialized = await rawRequest(port, {
    headers: legacyHeaders,
    body: { jsonrpc: '2.0', method: 'notifications/initialized' }
  });
  assertEqual(initialized.status, 202, 'notifications/initialized: HTTP status');

  const list = await rawRequest(port, {
    headers: legacyHeaders,
    body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }
  });
  const listResult = resultOf(list, 2, 'legacy tools/list');
  assert(
    Array.isArray(listResult.tools) && listResult.tools.some(tool => tool.name === 'create_element'),
    'legacy tools/list: create_element must be advertised'
  );
  assert(listResult.resultType === undefined, 'legacy tools/list: 2025-era results must not carry resultType');

  const id = 'http-legacy-rect';
  const call = await rawRequest(port, {
    headers: legacyHeaders,
    body: {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'create_element', arguments: { id, type: 'rectangle', x: 10, y: 20, width: 100, height: 50 } }
    }
  });
  const callResult = resultOf(call, 3, 'legacy tools/call create_element');
  assert(callResult.isError !== true, `legacy tools/call: tool reported an error: ${JSON.stringify(callResult.content)}`);

  const rest = await restElement(baseUrl, id);
  assertEqual(rest.status, 200, 'REST GET of the element created over legacy MCP: HTTP status');
  assertEqual(rest.element?.type, 'rectangle', 'REST GET of the element created over legacy MCP: type');
  assertEqual(rest.element?.x, 10, 'REST GET of the element created over legacy MCP: x');
}

async function checkModernEra({ port, baseUrl }) {
  const list = await rawRequest(port, {
    headers: modernHeaders('tools/list'),
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
  });
  const listResult = resultOf(list, 1, 'modern tools/list');
  assertEqual(listResult.resultType, 'complete', 'modern tools/list: resultType');
  assertEqual(listResult._meta?.[SERVER_INFO_META_KEY]?.name, 'mcp-excalidraw-server', 'modern tools/list: serverInfo.name');
  assert(
    Array.isArray(listResult.tools) && listResult.tools.some(tool => tool.name === 'create_element'),
    'modern tools/list: create_element must be advertised'
  );
  assert(list.headers['mcp-session-id'] === undefined, 'modern tools/list: stateless era must not issue Mcp-Session-Id');

  const id = 'http-modern-ellipse';
  const call = await rawRequest(port, {
    headers: modernHeaders('tools/call', 'create_element'),
    body: {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'create_element',
        arguments: { id, type: 'ellipse', x: 300, y: 40, width: 80, height: 80 },
        _meta: envelope()
      }
    }
  });
  const callResult = resultOf(call, 2, 'modern tools/call create_element');
  assert(callResult.isError !== true, `modern tools/call: tool reported an error: ${JSON.stringify(callResult.content)}`);
  assertEqual(callResult.resultType, 'complete', 'modern tools/call: resultType');

  const rest = await restElement(baseUrl, id);
  assertEqual(rest.status, 200, 'REST GET of the element created over modern MCP: HTTP status');
  assertEqual(rest.element?.type, 'ellipse', 'REST GET of the element created over modern MCP: type');
  assertEqual(rest.element?.x, 300, 'REST GET of the element created over modern MCP: x');
}

async function checkModernRequiresMethodHeader({ port }) {
  const response = await rawRequest(port, {
    headers: { 'mcp-protocol-version': MODERN_VERSION },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
  });
  assertEqual(response.status, 400, 'missing Mcp-Method: HTTP status');
  assertEqual(JSON.parse(response.text).error?.code, HEADER_MISMATCH_CODE, 'missing Mcp-Method: JSON-RPC error code');
}

async function checkForeignOriginRejected({ port }) {
  const response = await rawRequest(port, {
    headers: { ...modernHeaders('tools/list'), origin: 'https://evil.example' },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
  });
  assertEqual(response.status, 403, 'foreign Origin on loopback: HTTP status');
}

async function checkForeignHostRejected({ port }) {
  const response = await rawRequest(port, {
    headers: { ...modernHeaders('tools/list'), host: `evil.example:${port}` },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
  });
  assertEqual(response.status, 403, 'foreign Host on loopback: HTTP status');
}

async function checkLocalOriginAccepted({ port }) {
  const response = await rawRequest(port, {
    headers: { ...modernHeaders('tools/list'), origin: `http://localhost:${port}` },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
  });
  resultOf(response, 1, 'localhost Origin on loopback');
}

async function checkRestUnaffectedByMcpGuard({ port }) {
  // The DNS-rebinding guard is scoped to /mcp; the REST API keeps its
  // existing behaviour for any Host header.
  const response = await rawRequest(port, { method: 'GET', path: '/health', headers: { host: `evil.example:${port}` } });
  assertEqual(response.status, 200, 'REST /health with a foreign Host: HTTP status');
}

async function checkPublicBaseUrl() {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const canvas = spawnCanvas(port, { PUBLIC_BASE_URL: `https://${PUBLIC_HOST}/` });
  try {
    await waitForHealth(baseUrl, canvas);
    const viaProxy = await rawRequest(port, {
      headers: { ...modernHeaders('tools/list'), host: PUBLIC_HOST, origin: `https://${PUBLIC_HOST}` },
      body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope() } }
    });
    resultOf(viaProxy, 1, 'PUBLIC_BASE_URL host through a reverse proxy');

    const foreign = await rawRequest(port, {
      headers: { ...modernHeaders('tools/list'), host: 'evil.example' },
      body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: envelope() } }
    });
    assertEqual(foreign.status, 403, 'foreign Host with PUBLIC_BASE_URL set: HTTP status');
  } finally {
    canvas.child.kill('SIGKILL');
  }
}

async function checkInvalidPublicBaseUrl() {
  const port = await freePort();
  const canvas = spawnCanvas(port, { PUBLIC_BASE_URL: 'ftp://not-http.example' });
  let code;
  try {
    code = await waitForExit(canvas.child);
  } finally {
    if (canvas.child.exitCode === null) canvas.child.kill('SIGKILL');
  }
  assert(code !== 0, `invalid PUBLIC_BASE_URL: expected a non-zero exit, got ${code}`);
  assert(canvas.output().includes('PUBLIC_BASE_URL'), `invalid PUBLIC_BASE_URL: error must name the variable, got ${JSON.stringify(canvas.output())}`);
}

async function main() {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const canvas = spawnCanvas(port);
  const ctx = { port, baseUrl };

  const checks = [
    [`${LEGACY_VERSION} client: initialize, tools/list, create_element`, () => checkLegacyEra(ctx)],
    [`${MODERN_VERSION} client: stateless tools/list and create_element`, () => checkModernEra(ctx)],
    [`${MODERN_VERSION} requests without Mcp-Method are refused`, () => checkModernRequiresMethodHeader(ctx)],
    ['foreign Origin is rejected on loopback', () => checkForeignOriginRejected(ctx)],
    ['foreign Host is rejected on loopback', () => checkForeignHostRejected(ctx)],
    ['localhost Origin is accepted on loopback', () => checkLocalOriginAccepted(ctx)],
    ['REST API is unaffected by the /mcp guard', () => checkRestUnaffectedByMcpGuard(ctx)],
    ['PUBLIC_BASE_URL host is accepted, others still rejected', checkPublicBaseUrl],
    ['invalid PUBLIC_BASE_URL fails startup', checkInvalidPublicBaseUrl]
  ];

  let failed = 0;
  try {
    await waitForHealth(baseUrl, canvas);
    for (const [name, check] of checks) {
      try {
        await check();
        console.log(`ok - ${name}`);
      } catch (error) {
        failed += 1;
        console.error(`not ok - ${name}`);
        console.error(`  ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } catch (error) {
    failed = checks.length;
    console.error(`not ok - canvas startup\n  ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    canvas.child.kill('SIGKILL');
  }

  killAll();
  if (failed > 0) {
    // Scratch is kept on failure for the logs.
    console.error(`scratch kept: ${scratch}`);
    console.error(`${failed} of ${checks.length} HTTP MCP wire checks failed.`);
    process.exit(1);
  }
  rmSync(scratch, { recursive: true, force: true });
  console.log(`All ${checks.length} HTTP MCP wire checks passed using ${runtimeName}.`);
}

await main();
