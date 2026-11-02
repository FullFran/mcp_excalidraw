import express from 'express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { IncomingMessage } from 'node:http';
import type { AuthInfo } from '@modelcontextprotocol/server';
import logger from '../utils/logger.js';
import { MCP_AUTH_INFO_LOCAL } from '../core/mcp-http.js';
import { WHITEBOARD_SCOPE } from './config.js';
import type { AuthOnConfig } from './config.js';
import { Signer, constantTimeEqual, hashToken, isValidCodeChallenge, randomToken, verifyPkceS256 } from './crypto.js';
import { AuthStore } from './store.js';
import type { RefreshTokenRecord, TokenRecord } from './store.js';
import {
  ClientError,
  CimdResolver,
  authenticateClient,
  redirectUriMatches,
  registerClient,
  resolveClient
} from './clients.js';
import type { ResolvedClient } from './clients.js';
import type { SafeFetchOptions } from './ssrf.js';
import { GitHubLoginError, pollDeviceLogin, requestDeviceCode } from './github.js';
import { rateLimit } from './rate-limit.js';
import { sendConsentPage, sendDevicePage, sendDeviceScript, sendErrorPage, sendLoginPage } from './pages.js';

export { resolveAuthConfig, AuthConfigError, WHITEBOARD_SCOPE } from './config.js';
export type { AuthConfig, AuthOnConfig } from './config.js';

/** Request header carrying the per-process credential of in-process MCP tools. */
export const INTERNAL_AUTH_HEADER = 'x-excalidraw-internal-auth';

const SESSION_PURPOSE = 'session';
const DEVICE_PURPOSE = 'device-login';
const CONSENT_PURPOSE = 'consent';
const CONSENT_TTL_SECONDS = 600;
/** Device codes live as long as GitHub says, but never longer than this. */
const MAX_DEVICE_LOGIN_SECONDS = 15 * 60;
/** Device logins waiting for GitHub at once, across all clients. */
const MAX_PENDING_DEVICE_LOGINS = 20;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export interface AuthDeps {
  /** Options for fetching Client ID Metadata Documents (tests inject a guard and CA). */
  cimdFetch?: SafeFetchOptions;
}

export interface Session {
  login: string;
  sid: string;
}

interface CodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  login: string;
  expiresAt: number;
  used: boolean;
  familyId?: string;
}

type DeviceOutcome =
  | { kind: 'success'; login: string }
  | { kind: 'not_allowed'; login: string }
  | { kind: 'expired' }
  | { kind: 'denied' }
  | { kind: 'error' };

/** A GitHub device login, reachable only through its browser's binding cookie. */
interface DeviceLogin {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  /** Epoch milliseconds. */
  expiresAt: number;
  intervalMs: number;
  nextPollAt: number;
  returnTo: string;
  outcome?: DeviceOutcome;
  polling?: Promise<void>;
}

export type WebSocketVerdict = { ok: true } | { ok: false; status: 401 | 403; message: string };

export interface Auth {
  /** Metadata documents and `/oauth/*` endpoints. Mount first, at the app root. */
  router: express.Router;
  /** Resource-server check for `/mcp`, plugged into the MCP router's auth seam. */
  mcpBearer: RequestHandler;
  /** Session/bearer gate for the canvas page, static assets and `/api/*`. */
  protect: RequestHandler;
  /** Decides a WebSocket upgrade. */
  verifyWebSocket(req: IncomingMessage): WebSocketVerdict;
  /** Header value in-process MCP tools send to reach `/api/*`. */
  internalToken: string;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function single(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    if (cookies.has(name)) continue;
    try {
      cookies.set(name, decodeURIComponent(part.slice(index + 1).trim()));
    } catch {
      // ignore malformed values
    }
  }
  return cookies;
}

function bearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i.exec(header);
  return match?.[1];
}

/** Same-origin relative path, to avoid an open redirect through `return_to`. */
/**
 * A same-origin path to go back to after sign-in, or "/". Browsers drop ASCII
 * tab/CR/LF from URLs and treat "\" like "/", so "/\t/evil" or "/\evil" would
 * navigate off-site through location.assign; anything with control characters
 * or backslashes is refused, and the result must resolve to our own origin.
 */
function safeReturnPath(value: string | undefined): string {
  if (!value || value.length > 4096 || !value.startsWith('/') || value.startsWith('//')) return '/';
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return '/';
  try {
    const base = new URL('https://return-path.invalid');
    const resolved = new URL(value, base);
    if (resolved.origin !== base.origin) return '/';
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return '/';
  }
}

function oauthError(res: Response, status: number, error: string, description: string, extraHeaders: Record<string, string> = {}): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  for (const [name, value] of Object.entries(extraHeaders)) res.setHeader(name, value);
  res.status(status).json({ error, error_description: description });
}

export function createAuth(config: AuthOnConfig, deps: AuthDeps = {}): Auth {
  const store = new AuthStore(config.storePath);
  const signer = new Signer(config.secret);
  const cimd = new CimdResolver(deps.cimdFetch);
  const codes = new Map<string, CodeRecord>();
  // nonce (from the browser's signed cookie) -> pending GitHub device login
  const deviceLogins = new Map<string, DeviceLogin>();
  // consent ticket id -> expiry (epoch seconds); tickets are single use
  const usedTickets = new Map<string, number>();
  const internalToken = randomToken(32);
  const issuerOrigin = config.issuer;
  const cookiePrefix = config.secureCookies ? '__Host-' : '';
  const sessionCookie = `${cookiePrefix}wb_session`;
  const deviceCookie = `${cookiePrefix}wb_device`;
  const resourceMetadataUrl = `${config.issuer}/.well-known/oauth-protected-resource`;

  type SameSite = 'Lax' | 'Strict';
  const cookieAttributes = (maxAge: number, sameSite: SameSite): string =>
    `Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${config.secureCookies ? '; Secure' : ''}`;
  const setCookie = (res: Response, name: string, value: string, maxAge: number, sameSite: SameSite = 'Lax'): void => {
    res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; ${cookieAttributes(maxAge, sameSite)}`);
  };
  const clearCookie = (res: Response, name: string, sameSite: SameSite = 'Lax'): void => {
    res.append('Set-Cookie', `${name}=; ${cookieAttributes(0, sameSite)}`);
  };

  const readSession = (cookieHeader: string | undefined): Session | null => {
    const payload = signer.verify<{ sub?: unknown; sid?: unknown }>(SESSION_PURPOSE, parseCookies(cookieHeader).get(sessionCookie));
    if (!payload || typeof payload.sub !== 'string' || typeof payload.sid !== 'string') return null;
    // Re-checked on every request: removing a login from the allowlist
    // (and restarting) ends its sessions.
    if (!config.allowedLogins.has(payload.sub.toLowerCase())) return null;
    return { login: payload.sub, sid: payload.sid };
  };

  const verifyAccessToken = (token: string | undefined):
    { ok: true; record: TokenRecord } | { ok: false; error: 'invalid_token' | 'insufficient_scope' | 'missing' } => {
    if (!token) return { ok: false, error: 'missing' };
    const record = store.getAccessToken(hashToken(token));
    // Audience check: the token must have been issued for this resource.
    if (!record || record.resource !== config.resource || !config.allowedLogins.has(record.login.toLowerCase())) {
      return { ok: false, error: 'invalid_token' };
    }
    if (!record.scope.split(' ').includes(WHITEBOARD_SCOPE)) return { ok: false, error: 'insufficient_scope' };
    return { ok: true, record };
  };

  const challenge = (error?: string, description?: string): string => {
    let value = `Bearer resource_metadata="${resourceMetadataUrl}", scope="${WHITEBOARD_SCOPE}"`;
    if (error) value += `, error="${error}"`;
    if (description) value += `, error_description="${description}"`;
    return value;
  };

  const sameOrigin = (req: { headers: IncomingMessage['headers'] }): boolean => {
    const origin = single(req.headers.origin);
    if (origin !== undefined) return origin === issuerOrigin;
    const referer = single(req.headers.referer);
    if (!referer) return false;
    try {
      return new URL(referer).origin === issuerOrigin;
    } catch {
      return false;
    }
  };

  const issueTokens = (client: ResolvedClient, login: string, scope: string, resource: string, familyId: string): Record<string, unknown> => {
    const accessToken = randomToken(32);
    const refreshToken = randomToken(32);
    const now = nowSeconds();
    const accessRecord: TokenRecord = {
      clientId: client.clientId, login, scope, resource, familyId, expiresAt: now + config.accessTokenTtlSeconds
    };
    const refreshRecord: RefreshTokenRecord = {
      clientId: client.clientId, login, scope, resource, familyId, expiresAt: now + config.refreshTokenTtlSeconds
    };
    store.extendFamily(familyId, refreshRecord.expiresAt);
    store.putTokens({ hash: hashToken(accessToken), record: accessRecord }, { hash: hashToken(refreshToken), record: refreshRecord });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope
    };
  };

  const pruneCodes = (): void => {
    const now = nowSeconds();
    // Used codes are kept a little longer so a replay is still recognised.
    for (const [key, record] of codes) if (record.expiresAt + 600 <= now) codes.delete(key);
  };

  const redirectWith = (res: Response, status: 302 | 303, redirectUri: string, params: Record<string, string | undefined>): void => {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(name, value);
    // RFC 9207: identify the issuer in every authorization response.
    url.searchParams.set('iss', config.issuer);
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(status, url.toString());
  };

  const loginLimiter = rateLimit({ windowMs: 60_000, max: 20, name: 'login' });
  // Each start asks GitHub for a device code.
  const deviceStartLimiter = rateLimit({ windowMs: 60_000, max: 5, name: 'sign-in' });
  const devicePollLimiter = rateLimit({ windowMs: 60_000, max: 60, name: 'sign-in status' });
  const tokenLimiter = rateLimit({ windowMs: 60_000, max: 60, name: 'token' });
  const registerLimiter = rateLimit({ windowMs: 60_000, max: 10, name: 'registration' });
  // Authorization requests can make the server fetch a client metadata document.
  const authorizeLimiter = rateLimit({ windowMs: 60_000, max: 60, name: 'authorization' });

  const router = express.Router();
  const urlencoded = express.urlencoded({ extended: false, limit: '16kb' });
  const json = express.json({ limit: '16kb' });

  // ---- Metadata (RFC 9728, RFC 8414) ----

  const resourceMetadata = (_req: Request, res: Response): void => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json({
      resource: config.resource,
      authorization_servers: [config.issuer],
      scopes_supported: [WHITEBOARD_SCOPE],
      bearer_methods_supported: ['header'],
      resource_name: 'Excalidraw whiteboard'
    });
  };
  router.get('/.well-known/oauth-protected-resource', resourceMetadata);
  router.get('/.well-known/oauth-protected-resource/mcp', resourceMetadata);

  router.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/oauth/authorize`,
      token_endpoint: `${config.issuer}/oauth/token`,
      registration_endpoint: `${config.issuer}/oauth/register`,
      scopes_supported: [WHITEBOARD_SCOPE],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true
    });
  });

  // ---- Dynamic Client Registration (RFC 7591) ----

  router.post('/oauth/register', registerLimiter, json, (req, res) => {
    try {
      const registration = registerClient(store, req.body);
      res.setHeader('Cache-Control', 'no-store');
      res.status(201).json(registration);
    } catch (error) {
      if (error instanceof ClientError) {
        oauthError(res, 400, error.code, error.message);
        return;
      }
      throw error;
    }
  });

  // ---- GitHub login (OAuth device flow) ----
  //
  // The browser that starts a device login gets a signed, HttpOnly,
  // SameSite=Strict cookie holding a random nonce; the device code itself
  // stays in this map. Only that browser can see the code, poll and complete
  // the login, so a code shown on one screen cannot be completed elsewhere.

  const pruneDeviceLogins = (): void => {
    const now = Date.now();
    for (const [nonce, record] of deviceLogins) if (record.expiresAt <= now) deviceLogins.delete(nonce);
  };

  const deviceRecord = (req: Request): { nonce: string; record: DeviceLogin } | null => {
    pruneDeviceLogins();
    const payload = signer.verify<{ n?: unknown }>(DEVICE_PURPOSE, parseCookies(req.headers.cookie).get(deviceCookie));
    if (!payload || typeof payload.n !== 'string') return null;
    const record = deviceLogins.get(payload.n);
    return record ? { nonce: payload.n, record } : null;
  };

  /** Polls GitHub for this login when its interval allows; one poll at a time. */
  const advanceDeviceLogin = async (record: DeviceLogin): Promise<void> => {
    if (record.outcome) return;
    if (record.polling) return record.polling;
    const now = Date.now();
    if (now >= record.expiresAt) {
      record.outcome = { kind: 'expired' };
      return;
    }
    if (now < record.nextPollAt) return;
    record.polling = (async () => {
      try {
        const result = await pollDeviceLogin(config, record.deviceCode);
        const after = Date.now();
        switch (result.kind) {
          case 'pending':
            record.nextPollAt = after + record.intervalMs;
            break;
          case 'slow_down':
            // RFC 8628 §3.5: add 5 s, or use GitHub's new interval if larger.
            record.intervalMs = Math.max(record.intervalMs + 5000, (result.intervalSeconds ?? 0) * 1000);
            record.nextPollAt = after + record.intervalMs;
            break;
          case 'expired':
            record.outcome = { kind: 'expired' };
            break;
          case 'denied':
            record.outcome = { kind: 'denied' };
            break;
          case 'error':
            logger.warn('GitHub device login failed', { reason: result.code });
            record.outcome = { kind: 'error' };
            break;
          case 'login':
            if (config.allowedLogins.has(result.login.toLowerCase())) {
              record.outcome = { kind: 'success', login: result.login };
            } else {
              logger.warn('GitHub login not in ALLOWED_GITHUB_LOGINS', { login: result.login });
              record.outcome = { kind: 'not_allowed', login: result.login };
            }
            break;
        }
      } catch (error) {
        if (!(error instanceof GitHubLoginError)) throw error;
        // GitHub unreachable: keep the login pending and try again later.
        logger.warn('GitHub device poll failed; will retry', { reason: error.message });
        record.nextPollAt = Date.now() + record.intervalMs;
      } finally {
        record.polling = undefined;
      }
    })();
    return record.polling;
  };

  const failurePage = (res: Response, outcome: Exclude<DeviceOutcome, { kind: 'success' }>): void => {
    switch (outcome.kind) {
      case 'not_allowed':
        sendErrorPage(res, 403, 'Account not allowed', `The GitHub account ${outcome.login} is not allowed to use this whiteboard.`, '/oauth/login');
        return;
      case 'expired':
        sendErrorPage(res, 400, 'Code expired', 'The sign-in code expired before it was entered on GitHub.', '/oauth/login');
        return;
      case 'denied':
        sendErrorPage(res, 400, 'Sign-in cancelled', 'The sign-in was cancelled on GitHub.', '/oauth/login');
        return;
      case 'error':
        sendErrorPage(res, 502, 'Sign-in failed', 'GitHub could not confirm the sign-in. Try again.', '/oauth/login');
    }
  };

  router.get('/oauth/login', loginLimiter, (req, res) => {
    sendLoginPage(res, safeReturnPath(single(req.query.return_to)));
  });

  router.post('/oauth/login', deviceStartLimiter, urlencoded, async (req, res, next) => {
    try {
      if (!sameOrigin(req)) {
        sendErrorPage(res, 403, 'Forbidden', 'Cross-site request rejected.');
        return;
      }
      pruneDeviceLogins();
      if (deviceLogins.size >= MAX_PENDING_DEVICE_LOGINS) {
        res.setHeader('Retry-After', '60');
        sendErrorPage(res, 503, 'Too many sign-ins', 'Too many sign-ins are waiting for GitHub right now. Try again in a few minutes.', '/oauth/login');
        return;
      }
      const returnTo = safeReturnPath(single(req.body?.return_to));
      let device;
      try {
        device = await requestDeviceCode(config);
      } catch (error) {
        if (error instanceof GitHubLoginError) {
          logger.warn('GitHub device code request failed', { reason: error.message });
          sendErrorPage(res, 502, 'Sign-in unavailable', 'GitHub did not start the sign-in. Check that Device Flow is enabled for the OAuth app, then try again.', '/oauth/login');
          return;
        }
        throw error;
      }
      const lifetimeSeconds = Math.min(device.expiresInSeconds, MAX_DEVICE_LOGIN_SECONDS);
      const now = Date.now();
      const nonce = randomToken(24);
      deviceLogins.set(nonce, {
        deviceCode: device.deviceCode,
        userCode: device.userCode,
        verificationUri: device.verificationUri,
        expiresAt: now + lifetimeSeconds * 1000,
        intervalMs: device.intervalSeconds * 1000,
        // RFC 8628 §3.5: wait one interval before the first poll.
        nextPollAt: now + device.intervalSeconds * 1000,
        returnTo
      });
      setCookie(res, deviceCookie, signer.sign(DEVICE_PURPOSE, { n: nonce }, lifetimeSeconds), lifetimeSeconds, 'Strict');
      res.setHeader('Cache-Control', 'no-store');
      res.redirect(303, '/oauth/device');
    } catch (error) {
      next(error);
    }
  });

  router.get('/oauth/device', loginLimiter, (req, res) => {
    const found = deviceRecord(req);
    if (!found) {
      clearCookie(res, deviceCookie, 'Strict');
      sendErrorPage(res, 400, 'No sign-in in progress', 'This sign-in expired or was not started in this browser.', '/oauth/login');
      return;
    }
    const { nonce, record } = found;
    if (record.outcome && record.outcome.kind !== 'success') {
      // Shown once, then forgotten.
      deviceLogins.delete(nonce);
      clearCookie(res, deviceCookie, 'Strict');
      failurePage(res, record.outcome);
      return;
    }
    sendDevicePage(res, {
      userCode: record.userCode,
      verificationUri: record.verificationUri,
      ...(config.github.appName ? { appName: config.github.appName } : {}),
      intervalSeconds: Math.ceil(record.intervalMs / 1000),
      expiresAt: record.expiresAt
    });
  });

  router.get('/oauth/device.js', (_req, res) => {
    sendDeviceScript(res);
  });

  router.post('/oauth/device/poll', devicePollLimiter, async (req, res, next) => {
    try {
      const wantsHtml = req.accepts(['json', 'html']) === 'html';
      res.setHeader('Cache-Control', 'no-store');
      if (!sameOrigin(req)) {
        res.status(403).json({ status: 'forbidden', error: 'Cross-site request rejected' });
        return;
      }
      const found = deviceRecord(req);
      if (!found) {
        if (wantsHtml) {
          res.redirect(303, '/oauth/device');
          return;
        }
        res.status(400).json({ status: 'unknown', error: 'No sign-in in progress in this browser' });
        return;
      }
      const { nonce, record } = found;
      await advanceDeviceLogin(record);
      const outcome = record.outcome;
      if (outcome?.kind === 'success') {
        deviceLogins.delete(nonce);
        clearCookie(res, deviceCookie, 'Strict');
        setCookie(res, sessionCookie, signer.sign(SESSION_PURPOSE, { sub: outcome.login, sid: randomToken(16) }, config.sessionTtlSeconds), config.sessionTtlSeconds);
        if (wantsHtml) {
          res.redirect(303, record.returnTo);
          return;
        }
        res.json({ status: 'complete', redirect: record.returnTo });
        return;
      }
      if (wantsHtml) {
        res.redirect(303, '/oauth/device');
        return;
      }
      if (outcome) {
        res.json({ status: 'failed', reason: outcome.kind });
        return;
      }
      res.json({ status: 'pending', interval: Math.ceil(record.intervalMs / 1000) });
    } catch (error) {
      next(error);
    }
  });

  router.post('/oauth/logout', urlencoded, (req, res) => {
    if (!sameOrigin(req)) {
      sendErrorPage(res, 403, 'Forbidden', 'Cross-site request rejected.');
      return;
    }
    clearCookie(res, sessionCookie);
    res.redirect(303, '/');
  });

  // ---- Authorization endpoint ----

  router.get('/oauth/authorize', authorizeLimiter, async (req, res, next) => {
    try {
      let client: ResolvedClient;
      try {
        client = await resolveClient(store, cimd, req.query.client_id);
      } catch (error) {
        if (error instanceof ClientError) {
          sendErrorPage(res, 400, 'Unknown application', error.message);
          return;
        }
        throw error;
      }
      const redirectUri = single(req.query.redirect_uri);
      if (!redirectUri || !redirectUriMatches(client.redirectUris, redirectUri)) {
        // Never redirect to an unregistered URI.
        sendErrorPage(res, 400, 'Invalid redirect', 'redirect_uri is missing or not registered for this client.');
        return;
      }
      const state = single(req.query.state);
      const fail = (error: string, description: string): void =>
        redirectWith(res, 302, redirectUri, { error, error_description: description, state });

      if (single(req.query.response_type) !== 'code') return fail('unsupported_response_type', 'response_type must be code');
      const codeChallenge = single(req.query.code_challenge);
      const method = single(req.query.code_challenge_method);
      if (!codeChallenge) return fail('invalid_request', 'PKCE code_challenge is required');
      if (method !== 'S256') return fail('invalid_request', 'code_challenge_method must be S256');
      if (!isValidCodeChallenge(codeChallenge)) return fail('invalid_request', 'malformed code_challenge');
      const requestedScope = single(req.query.scope)?.trim();
      const scopes = requestedScope ? requestedScope.split(/\s+/) : [WHITEBOARD_SCOPE];
      if (scopes.some(scope => scope !== WHITEBOARD_SCOPE)) return fail('invalid_scope', `only the "${WHITEBOARD_SCOPE}" scope is available`);
      const resources = req.query.resource === undefined ? [] : [req.query.resource].flat();
      if (resources.length > 1 || (resources.length === 1 && resources[0] !== config.resource)) {
        return fail('invalid_target', `resource must be ${config.resource}`);
      }

      const session = readSession(req.headers.cookie);
      if (!session) {
        res.setHeader('Cache-Control', 'no-store');
        res.redirect(302, `/oauth/login?return_to=${encodeURIComponent(req.originalUrl)}`);
        return;
      }
      const ticket = signer.sign(CONSENT_PURPOSE, {
        tid: randomToken(16),
        clientId: client.clientId,
        redirectUri,
        codeChallenge,
        scope: WHITEBOARD_SCOPE,
        resource: config.resource,
        state: state ?? null,
        sid: session.sid,
        login: session.login
      }, CONSENT_TTL_SECONDS);
      sendConsentPage(res, {
        ...(client.clientName ? { clientName: client.clientName } : {}),
        clientId: client.clientId,
        clientKind: client.kind,
        redirectUri,
        scope: WHITEBOARD_SCOPE,
        login: session.login,
        ticket
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/oauth/authorize', urlencoded, async (req, res, next) => {
    try {
      if (!sameOrigin(req)) {
        sendErrorPage(res, 403, 'Forbidden', 'Cross-site request rejected.');
        return;
      }
      const session = readSession(req.headers.cookie);
      const ticket = signer.verify<{
        tid: string; clientId: string; redirectUri: string; codeChallenge: string; scope: string;
        resource: string; state: string | null; sid: string; login: string;
      }>(CONSENT_PURPOSE, single(req.body?.ticket));
      if (!session || !ticket || typeof ticket.tid !== 'string' || ticket.sid !== session.sid || ticket.login !== session.login) {
        sendErrorPage(res, 400, 'Request expired', 'This approval request expired or belongs to another session. Start again from the application.');
        return;
      }
      // Single use, whatever the decision: burnt before any await.
      const nowTicket = nowSeconds();
      for (const [id, expiresAt] of usedTickets) if (expiresAt <= nowTicket) usedTickets.delete(id);
      if (usedTickets.has(ticket.tid)) {
        sendErrorPage(res, 400, 'Request already used', 'This approval request was already answered. Start again from the application.');
        return;
      }
      usedTickets.set(ticket.tid, ticket.exp);
      // The client could have changed its metadata document since the
      // consent page was shown; re-check the redirect against it.
      let client: ResolvedClient;
      try {
        client = await resolveClient(store, cimd, ticket.clientId);
      } catch (error) {
        if (error instanceof ClientError) {
          sendErrorPage(res, 400, 'Unknown application', error.message);
          return;
        }
        throw error;
      }
      if (!redirectUriMatches(client.redirectUris, ticket.redirectUri)) {
        sendErrorPage(res, 400, 'Invalid redirect', 'redirect_uri is no longer registered for this client.');
        return;
      }
      const state = ticket.state ?? undefined;
      if (single(req.body?.decision) !== 'approve') {
        redirectWith(res, 303, ticket.redirectUri, { error: 'access_denied', error_description: 'the user denied access', state });
        return;
      }
      pruneCodes();
      const code = randomToken(32);
      codes.set(hashToken(code), {
        clientId: client.clientId,
        redirectUri: ticket.redirectUri,
        codeChallenge: ticket.codeChallenge,
        scope: ticket.scope,
        resource: ticket.resource,
        login: session.login,
        expiresAt: nowSeconds() + config.authorizationCodeTtlSeconds,
        used: false
      });
      redirectWith(res, 303, ticket.redirectUri, { code, state });
    } catch (error) {
      next(error);
    }
  });

  // ---- Token endpoint ----

  router.post('/oauth/token', tokenLimiter, urlencoded, async (req, res, next) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      let clientId = single(body.client_id);
      let clientSecret = single(body.client_secret);
      let usedBasic = false;
      const basic = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(req.headers.authorization ?? '');
      if (basic) {
        if (clientSecret !== undefined) return oauthError(res, 400, 'invalid_request', 'use one client authentication method');
        const decoded = Buffer.from(basic[1]!, 'base64').toString('utf8');
        const colon = decoded.indexOf(':');
        if (colon < 0) return oauthError(res, 401, 'invalid_client', 'malformed Basic credentials', { 'WWW-Authenticate': 'Basic' });
        let basicId: string;
        try {
          basicId = decodeURIComponent(decoded.slice(0, colon));
          clientSecret = decodeURIComponent(decoded.slice(colon + 1));
        } catch {
          return oauthError(res, 401, 'invalid_client', 'malformed Basic credentials', { 'WWW-Authenticate': 'Basic' });
        }
        if (clientId !== undefined && clientId !== basicId) return oauthError(res, 400, 'invalid_request', 'client_id mismatch');
        clientId = basicId;
        usedBasic = true;
      }
      let client: ResolvedClient;
      try {
        client = await resolveClient(store, cimd, clientId);
      } catch (error) {
        if (error instanceof ClientError) return oauthError(res, 401, 'invalid_client', error.message, usedBasic ? { 'WWW-Authenticate': 'Basic' } : {});
        throw error;
      }
      if (!authenticateClient(client, clientSecret)) {
        return oauthError(res, 401, 'invalid_client', 'client authentication failed', usedBasic ? { 'WWW-Authenticate': 'Basic' } : {});
      }
      const resources = body.resource === undefined ? [] : [body.resource].flat();
      if (resources.length > 1 || (resources.length === 1 && resources[0] !== config.resource)) {
        return oauthError(res, 400, 'invalid_target', `resource must be ${config.resource}`);
      }

      const grantType = single(body.grant_type);
      if (grantType === 'authorization_code') {
        const code = single(body.code);
        const record = code ? codes.get(hashToken(code)) : undefined;
        if (!record || record.clientId !== client.clientId) return oauthError(res, 400, 'invalid_grant', 'unknown authorization code');
        if (record.used) {
          // RFC 6749 §4.1.2: a replayed code revokes what it issued.
          if (record.familyId) store.revokeFamily(record.familyId);
          logger.warn('Authorization code replayed; revoked its tokens', { clientId: client.clientId });
          return oauthError(res, 400, 'invalid_grant', 'authorization code already used');
        }
        // Single use: burnt on first presentation, whatever the outcome.
        record.used = true;
        if (record.expiresAt <= nowSeconds()) return oauthError(res, 400, 'invalid_grant', 'authorization code expired');
        if (single(body.redirect_uri) !== record.redirectUri) return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request');
        const verifier = single(body.code_verifier);
        if (!verifier || !verifyPkceS256(verifier, record.codeChallenge)) return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed');
        const familyId = store.createFamily(nowSeconds() + config.refreshTokenTtlSeconds);
        record.familyId = familyId;
        const tokens = issueTokens(client, record.login, record.scope, record.resource, familyId);
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.json(tokens);
        return;
      }
      if (grantType === 'refresh_token') {
        const presented = single(body.refresh_token);
        const hash = presented ? hashToken(presented) : undefined;
        const record = hash ? store.getRefreshToken(hash) : undefined;
        if (!hash || !record || record.clientId !== client.clientId) return oauthError(res, 400, 'invalid_grant', 'unknown refresh token');
        if (record.usedAt !== undefined) {
          // Rotation: a refresh token is valid once. Reuse means it leaked.
          store.revokeFamily(record.familyId);
          logger.warn('Refresh token reused; revoked its token family', { clientId: client.clientId });
          return oauthError(res, 400, 'invalid_grant', 'refresh token already used');
        }
        if (!store.isFamilyActive(record.familyId)) return oauthError(res, 400, 'invalid_grant', 'refresh token revoked');
        if (!config.allowedLogins.has(record.login.toLowerCase())) return oauthError(res, 400, 'invalid_grant', 'account no longer allowed');
        const requestedScope = single(body.scope)?.trim();
        if (requestedScope && requestedScope.split(/\s+/).some(scope => !record.scope.split(' ').includes(scope))) {
          return oauthError(res, 400, 'invalid_scope', 'scope exceeds the original grant');
        }
        store.markRefreshTokenUsed(hash);
        const tokens = issueTokens(client, record.login, record.scope, record.resource, record.familyId);
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.json(tokens);
        return;
      }
      oauthError(res, 400, 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
    } catch (error) {
      next(error);
    }
  });

  // ---- Resource server: /mcp ----

  const mcpBearer: RequestHandler = (req, res, next) => {
    const result = verifyAccessToken(bearerToken(req.headers.authorization));
    if (!result.ok) {
      if (result.error === 'insufficient_scope') {
        res.setHeader('WWW-Authenticate', challenge('insufficient_scope', 'the whiteboard scope is required'));
        res.status(403).json({ error: 'insufficient_scope' });
        return;
      }
      res.setHeader('WWW-Authenticate', result.error === 'missing' ? challenge() : challenge('invalid_token', 'the access token is invalid or expired'));
      res.status(401).json({ error: result.error === 'missing' ? 'unauthorized' : 'invalid_token' });
      return;
    }
    const authInfo: AuthInfo = {
      token: bearerToken(req.headers.authorization)!,
      clientId: result.record.clientId,
      scopes: result.record.scope.split(' '),
      expiresAt: result.record.expiresAt,
      resource: new URL(result.record.resource),
      extra: { login: result.record.login }
    };
    res.locals[MCP_AUTH_INFO_LOCAL] = authInfo;
    next();
  };

  // ---- Canvas, static assets and REST API ----

  const isInternal = (req: Request): boolean => {
    const presented = single(req.headers[INTERNAL_AUTH_HEADER]);
    return presented !== undefined && constantTimeEqual(presented, internalToken);
  };

  const protect: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    // Express matches routes case-insensitively (`/API/elements` reaches the
    // `/api/elements` handler), so paths are classified the same way.
    const path = req.path.toLowerCase();
    // `/health` answers without credentials (it leaks nothing when auth is
    // on); `/mcp` has its own bearer check in the MCP router.
    if (path === '/health' || path === '/mcp' || path === '/mcp/') return next();
    if (isInternal(req)) return next();

    if (path.startsWith('/api/') || path === '/api') {
      const token = bearerToken(req.headers.authorization);
      if (token) {
        const result = verifyAccessToken(token);
        if (result.ok) return next();
        const status = result.error === 'insufficient_scope' ? 403 : 401;
        res.setHeader('WWW-Authenticate', challenge(result.error === 'missing' ? undefined : result.error));
        res.status(status).json({ success: false, error: 'Unauthorized' });
        return;
      }
      if (readSession(req.headers.cookie)) {
        if (!SAFE_METHODS.has(req.method) && !sameOrigin(req)) {
          res.status(403).json({ success: false, error: 'Cross-site request rejected' });
          return;
        }
        return next();
      }
      res.setHeader('WWW-Authenticate', challenge());
      res.status(401).json({ success: false, error: 'Unauthorized' });
      return;
    }

    if (readSession(req.headers.cookie)) {
      // Any write authenticated by the cookie, whatever the path, must come
      // from our own pages.
      if (!SAFE_METHODS.has(req.method) && !sameOrigin(req)) {
        res.status(403).json({ success: false, error: 'Cross-site request rejected' });
        return;
      }
      return next();
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      res.setHeader('Cache-Control', 'no-store');
      res.redirect(302, `/oauth/login?return_to=${encodeURIComponent(req.originalUrl)}`);
      return;
    }
    res.status(401).json({ success: false, error: 'Unauthorized' });
  };

  const verifyWebSocket = (req: IncomingMessage): WebSocketVerdict => {
    const origin = single(req.headers.origin);
    if (origin !== undefined && origin !== issuerOrigin) {
      return { ok: false, status: 403, message: 'Origin not allowed' };
    }
    const token = bearerToken(req.headers.authorization);
    if (token) {
      const result = verifyAccessToken(token);
      return result.ok ? { ok: true } : { ok: false, status: 401, message: 'Invalid access token' };
    }
    if (readSession(req.headers.cookie)) {
      // A cookie is sent by the browser on any page's behalf: require the
      // page to be ours.
      if (origin === undefined) return { ok: false, status: 403, message: 'Origin required' };
      return { ok: true };
    }
    return { ok: false, status: 401, message: 'Unauthorized' };
  };

  return { router, mcpBearer, protect, verifyWebSocket, internalToken };
}
