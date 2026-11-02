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
import { GitHubLoginError, exchangeGitHubCode, githubAuthorizeUrl } from './github.js';
import { rateLimit } from './rate-limit.js';
import { sendConsentPage, sendErrorPage } from './pages.js';

export { resolveAuthConfig, AuthConfigError, WHITEBOARD_SCOPE } from './config.js';
export type { AuthConfig, AuthOnConfig } from './config.js';

/** Request header carrying the per-process credential of in-process MCP tools. */
export const INTERNAL_AUTH_HEADER = 'x-excalidraw-internal-auth';

const SESSION_PURPOSE = 'session';
const GITHUB_STATE_PURPOSE = 'github-state';
const CONSENT_PURPOSE = 'consent';
const GITHUB_STATE_TTL_SECONDS = 600;
const CONSENT_TTL_SECONDS = 600;
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
function safeReturnPath(value: string | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\') || value.length > 4096) return '/';
  return value;
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
  const internalToken = randomToken(32);
  const issuerOrigin = config.issuer;
  const cookiePrefix = config.secureCookies ? '__Host-' : '';
  const sessionCookie = `${cookiePrefix}wb_session`;
  const stateCookie = `${cookiePrefix}wb_github_state`;
  const resourceMetadataUrl = `${config.issuer}/.well-known/oauth-protected-resource`;
  const githubCallbackUrl = `${config.issuer}/oauth/github/callback`;

  const cookieAttributes = (maxAge: number): string =>
    `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${config.secureCookies ? '; Secure' : ''}`;
  const setCookie = (res: Response, name: string, value: string, maxAge: number): void => {
    res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; ${cookieAttributes(maxAge)}`);
  };
  const clearCookie = (res: Response, name: string): void => {
    res.append('Set-Cookie', `${name}=; ${cookieAttributes(0)}`);
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

  // ---- GitHub login ----

  router.get('/oauth/login', loginLimiter, (req, res) => {
    const returnTo = safeReturnPath(single(req.query.return_to));
    const nonce = randomToken(24);
    setCookie(res, stateCookie, signer.sign(GITHUB_STATE_PURPOSE, { nonce, returnTo }, GITHUB_STATE_TTL_SECONDS), GITHUB_STATE_TTL_SECONDS);
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, githubAuthorizeUrl(config, nonce, githubCallbackUrl));
  });

  router.get('/oauth/github/callback', loginLimiter, async (req, res, next) => {
    try {
      const statePayload = signer.verify<{ nonce?: unknown; returnTo?: unknown }>(
        GITHUB_STATE_PURPOSE, parseCookies(req.headers.cookie).get(stateCookie)
      );
      clearCookie(res, stateCookie);
      const state = single(req.query.state);
      if (!statePayload || typeof statePayload.nonce !== 'string' || !state || !constantTimeEqual(state, statePayload.nonce)) {
        sendErrorPage(res, 400, 'Login failed', 'The login request expired or did not start here. Start again from the application.');
        return;
      }
      const code = single(req.query.code);
      if (!code) {
        sendErrorPage(res, 400, 'Login cancelled', 'GitHub did not return an authorization code.');
        return;
      }
      let login: string;
      try {
        login = await exchangeGitHubCode(config, code, githubCallbackUrl);
      } catch (error) {
        if (error instanceof GitHubLoginError) {
          logger.warn('GitHub login failed', { reason: error.message });
          sendErrorPage(res, 502, 'Login failed', 'GitHub could not confirm the login. Try again.');
          return;
        }
        throw error;
      }
      if (!config.allowedLogins.has(login.toLowerCase())) {
        logger.warn('GitHub login not in ALLOWED_GITHUB_LOGINS', { login });
        sendErrorPage(res, 403, 'Account not allowed', `The GitHub account ${login} is not allowed to use this whiteboard.`);
        return;
      }
      setCookie(res, sessionCookie, signer.sign(SESSION_PURPOSE, { sub: login, sid: randomToken(16) }, config.sessionTtlSeconds), config.sessionTtlSeconds);
      res.setHeader('Cache-Control', 'no-store');
      res.redirect(302, safeReturnPath(typeof statePayload.returnTo === 'string' ? statePayload.returnTo : undefined));
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
        clientId: string; redirectUri: string; codeChallenge: string; scope: string;
        resource: string; state: string | null; sid: string; login: string;
      }>(CONSENT_PURPOSE, single(req.body?.ticket));
      if (!session || !ticket || ticket.sid !== session.sid || ticket.login !== session.login) {
        sendErrorPage(res, 400, 'Request expired', 'This approval request expired or belongs to another session. Start again from the application.');
        return;
      }
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
    // `/health` answers without credentials (it leaks nothing when auth is
    // on); `/mcp` has its own bearer check in the MCP router.
    if (req.path === '/health' || req.path === '/mcp' || req.path === '/mcp/') return next();
    if (isInternal(req)) return next();

    if (req.path.startsWith('/api/')) {
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

    if (readSession(req.headers.cookie)) return next();
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
