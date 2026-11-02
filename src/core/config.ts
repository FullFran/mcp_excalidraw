import dotenv from 'dotenv';

// Load environment variables once for every entry point (MCP server, CLI, canvas server)
dotenv.config();

// Express server configuration.
// `let` on purpose: ES module exports are live bindings, so when the canvas
// server hosts the MCP endpoint itself (`/mcp`) it repoints every importer at
// its own listener via `useInProcessCanvasUrl` — a tool call over HTTP must
// mutate the same in-memory canvas the REST API serves.
export let EXPRESS_SERVER_URL = process.env.EXPRESS_SERVER_URL || 'http://127.0.0.1:3000';

// Extra headers for every request to EXPRESS_SERVER_URL. Empty unless the
// canvas server hosts the tools itself with authentication on: then it hands
// the in-process tools a per-process credential so they can reach `/api/*`.
let canvasHeaders: Record<string, string> = {};

export function useInProcessCanvasUrl(url: string, internalHeaders: Record<string, string> = {}): void {
  EXPRESS_SERVER_URL = url.replace(/\/+$/, '');
  canvasHeaders = { ...internalHeaders };
}

/** Merges the in-process credential (if any) into a request's headers. */
export function withCanvasHeaders(init: RequestInit = {}): RequestInit {
  if (Object.keys(canvasHeaders).length === 0) return init;
  const headers = new Headers(init.headers);
  for (const [name, value] of Object.entries(canvasHeaders)) headers.set(name, value);
  return { ...init, headers };
}
export const ENABLE_CANVAS_SYNC = process.env.ENABLE_CANVAS_SYNC !== 'false'; // Default to true

// Opt-out for auto-starting the canvas server from the CLI / MCP server
export const EXCALIDRAW_NO_AUTOSTART = process.env.EXCALIDRAW_NO_AUTOSTART === '1';

// Safe file path validation base directory (see sanitizeFilePath)
export const ALLOWED_EXPORT_DIR = process.env.EXCALIDRAW_EXPORT_DIR || process.cwd();

// Share target for `share` / `export_to_excalidraw_url`. Defaults to excalidraw.com;
// point both at a self-hosted Excalidraw whose storage backend speaks the
// excalidraw-json API (e.g. alswl/excalidraw-storage-backend) to keep links in-house.
export const EXCALIDRAW_SHARE_UPLOAD_URL =
  process.env.EXCALIDRAW_SHARE_UPLOAD_URL?.trim() || 'https://json.excalidraw.com/api/v2/post/';
export const EXCALIDRAW_SHARE_BASE_URL =
  (process.env.EXCALIDRAW_SHARE_BASE_URL?.trim() || 'https://excalidraw.com').replace(/\/+$/, '');

/**
 * Public base URL of the canvas server as seen by remote clients, e.g.
 * `https://board.example.com` behind a reverse proxy. Used wherever an
 * absolute URL is produced (MCP endpoint URL, canvas links, and later OAuth
 * metadata). Returns `undefined` when `PUBLIC_BASE_URL` is unset; throws when
 * it is set but is not an absolute http(s) URL without query, fragment or
 * credentials. Trailing slashes are dropped so `${base}/mcp` is well-formed.
 */
export function resolvePublicBaseUrl(raw: string | undefined = process.env.PUBLIC_BASE_URL): string | undefined {
  const value = raw?.trim();
  if (!value) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`PUBLIC_BASE_URL must be an absolute http(s) URL, got ${JSON.stringify(value)}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`PUBLIC_BASE_URL must use http or https, got ${JSON.stringify(value)}`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`PUBLIC_BASE_URL must not carry credentials, a query or a fragment, got ${JSON.stringify(value)}`);
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
}

/**
 * The URL a human should open to see the canvas: the public base URL when
 * one is configured (and valid), otherwise the canvas server URL.
 */
export function canvasDisplayUrl(): string {
  try {
    return resolvePublicBaseUrl() ?? EXPRESS_SERVER_URL;
  } catch {
    return EXPRESS_SERVER_URL;
  }
}

/**
 * Express `trust proxy` setting from `TRUST_PROXY`. Off by default: only
 * enable it when a reverse proxy you control sits in front of the server,
 * otherwise clients can spoof `X-Forwarded-*`. Accepts `true`, a hop count
 * (`1`), or Express's address list syntax (`loopback`, `10.0.0.0/8, ::1`).
 */
export function resolveTrustProxy(raw: string | undefined = process.env.TRUST_PROXY): boolean | number | string {
  const value = raw?.trim();
  if (!value || value === 'false' || value === '0') return false;
  if (value === 'true') return true;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}
