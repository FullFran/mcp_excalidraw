import express from 'express';
import type { NextFunction, Request as ExpressRequest, RequestHandler, Response as ExpressResponse } from 'express';
import {
  createMcpHandler,
  hostHeaderValidationResponse,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  originValidationResponse
} from '@modelcontextprotocol/server';
import type { AuthInfo, McpHttpHandler } from '@modelcontextprotocol/server';
import logger from '../utils/logger.js';
import { excalidrawMcpServerFactory } from './mcp-server.js';

/** Path the Streamable HTTP MCP endpoint is mounted at on the canvas server. */
export const MCP_HTTP_PATH = '/mcp';

/**
 * Express `res.locals` key an authentication middleware sets to the verified
 * principal. The MCP handler forwards it to tool handlers and the server
 * factory as `authInfo`; it is never derived from request headers here.
 */
export const MCP_AUTH_INFO_LOCAL = 'mcpAuthInfo';

export interface McpHttpRouterOptions {
  /** The address the canvas server binds (`HOST`). Decides the DNS-rebinding guard. */
  bindHost: string;
  /** Validated `PUBLIC_BASE_URL`, when configured. Its hostname is allowed through the guard. */
  publicBaseUrl?: string;
  /**
   * Authentication seam: middlewares run after the Host/Origin guard and
   * before any MCP processing. A middleware rejects by answering the request
   * itself (e.g. 401 with `WWW-Authenticate`), or accepts by calling `next()`
   * after optionally setting `res.locals[MCP_AUTH_INFO_LOCAL]`. Empty by
   * default: `/mcp` is as open as the REST API on the same bind.
   */
  authMiddleware?: RequestHandler[];
  /** Request body limit, matching the REST API's JSON limit. */
  bodyLimit?: string;
}

const LOOPBACK_BIND_HOSTS = new Set(['localhost', '::1', '[::1]']);

export function isLoopbackBindHost(host: string): boolean {
  return LOOPBACK_BIND_HOSTS.has(host) || /^127(\.\d{1,3}){3}$/.test(host);
}

// Hop-by-hop headers describe the Node connection, not the request; they must
// not leak into the web-standard Request handed to the SDK.
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer'
]);

function toWebHeaders(req: ExpressRequest): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined || HOP_BY_HOP_HEADERS.has(name)) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  }
  return headers;
}

function toWebRequest(req: ExpressRequest, signal: AbortSignal): Request {
  let url: URL;
  try {
    url = new URL(req.originalUrl, `${req.protocol}://${req.get('host') ?? 'localhost'}`);
  } catch {
    url = new URL(req.originalUrl, 'http://localhost');
  }
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && Buffer.isBuffer(req.body) && req.body.length > 0;
  return new Request(url, {
    method: req.method,
    headers: toWebHeaders(req),
    ...(hasBody ? { body: req.body as Buffer } : {}),
    signal
  });
}

async function sendWebResponse(response: Response, res: ExpressResponse): Promise<void> {
  res.status(response.status);
  response.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });
  if (!response.body) {
    res.end();
    return;
  }
  // SSE answers must reach the client frame by frame, not once buffered.
  res.flushHeaders();
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
    }
    res.end();
  } catch (error) {
    // The client went away (abort) or the stream failed mid-flight.
    logger.debug('MCP HTTP response stream ended early', { error: (error as Error).message });
    res.destroy();
  }
}

/**
 * Host/Origin validation against DNS rebinding and cross-site requests. Active
 * when the server binds loopback — the case where a browser page could reach
 * it through a hostname it controls. The public base URL's hostname is
 * allowed so a reverse proxy on the same machine can forward with its own
 * Host header. Non-loopback binds rely on the authentication seam instead.
 */
function dnsRebindingGuard(options: McpHttpRouterOptions): RequestHandler {
  if (!isLoopbackBindHost(options.bindHost)) {
    return (_req, _res, next) => next();
  }
  const publicHost = options.publicBaseUrl ? new URL(options.publicBaseUrl).hostname : undefined;
  const allowedHosts = [...localhostAllowedHostnames(), ...(publicHost ? [publicHost] : [])];
  const allowedOrigins = [...localhostAllowedOrigins(), ...(publicHost ? [publicHost] : [])];

  return async (req, res, next) => {
    const probe = new Request('http://localhost/', { headers: toWebHeaders(req) });
    const rejected = hostHeaderValidationResponse(probe, allowedHosts) ?? originValidationResponse(probe, allowedOrigins);
    if (!rejected) {
      next();
      return;
    }
    logger.warn('Rejected MCP HTTP request failing Host/Origin validation', {
      host: req.headers.host,
      origin: req.headers.origin
    });
    await sendWebResponse(rejected, res);
  };
}

/**
 * Builds the Express router serving MCP over Streamable HTTP. Both protocol
 * eras are handled by the SDK's `createMcpHandler`: 2026-07-28 requests
 * (per-request `_meta` envelope, `Mcp-Method`/`Mcp-Name` headers) on its
 * modern path, and 2025-era clients (`initialize` handshake) through its
 * stateless legacy fallback — both backed by the same server factory as stdio.
 *
 * Mount it before any JSON body parser: the SDK reads the raw body itself.
 */
export function createMcpHttpRouter(options: McpHttpRouterOptions): { router: express.Router; handler: McpHttpHandler } {
  const handler = createMcpHandler(excalidrawMcpServerFactory, {
    // Reporting only: rejected requests are already answered on the wire.
    onerror: error => {
      logger.debug('MCP HTTP request error', { name: error.name, message: error.message });
    }
  });

  const serve = async (req: ExpressRequest, res: ExpressResponse, next: NextFunction): Promise<void> => {
    const controller = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) controller.abort();
    });
    try {
      const authInfo = res.locals[MCP_AUTH_INFO_LOCAL] as AuthInfo | undefined;
      const response = await handler.fetch(toWebRequest(req, controller.signal), authInfo ? { authInfo } : undefined);
      await sendWebResponse(response, res);
    } catch (error) {
      next(error);
    }
  };

  const router = express.Router();
  // Exactly `/mcp` (and `/mcp/`): subpaths fall through to the app's 404.
  router.all(
    '/',
    dnsRebindingGuard(options),
    ...(options.authMiddleware ?? []),
    express.raw({ type: () => true, limit: options.bodyLimit ?? '10mb' }),
    serve
  );
  return { router, handler };
}
