import { randomToken, hashToken, constantTimeEqual } from './crypto.js';
import { safeFetch, SafeFetchError } from './ssrf.js';
import type { SafeFetchOptions } from './ssrf.js';
import type { AuthStore, ClientAuthMethod, RegisteredClient } from './store.js';

/** Upper bound on clients registered through DCR (open registration). */
export const MAX_REGISTERED_CLIENTS = 200;
const MAX_REDIRECT_URIS = 10;
const MAX_URI_LENGTH = 2000;
const MAX_CLIENT_NAME_LENGTH = 100;
const LOOPBACK_REDIRECT_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

export class ClientError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'ClientError';
  }
}

/** A client as the authorization endpoint sees it, whatever its origin. */
export interface ResolvedClient {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  authMethod: ClientAuthMethod;
  secretHash?: string;
  kind: 'dcr' | 'cimd';
}

/**
 * Redirect URI policy: any https URI (ChatGPT's
 * `https://chatgpt.com/connector_platform_oauth_redirect` included), or an
 * http loopback URI for native/CLI clients (RFC 8252). No fragments, no
 * credentials, no custom schemes.
 */
export function isAllowedRedirectUri(raw: unknown): raw is string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URI_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.hash || raw.includes('#') || url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && LOOPBACK_REDIRECT_HOSTS.has(url.hostname);
}

/**
 * Exact string match against the registered URIs; for http loopback URIs the
 * port may differ (RFC 8252 §7.3: CLI clients bind an ephemeral port).
 */
export function redirectUriMatches(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  let target: URL;
  try {
    target = new URL(requested);
  } catch {
    return false;
  }
  if (target.protocol !== 'http:' || !LOOPBACK_REDIRECT_HOSTS.has(target.hostname)) return false;
  return registered.some(candidate => {
    try {
      const url = new URL(candidate);
      return url.protocol === 'http:' && url.hostname === target.hostname &&
        url.pathname === target.pathname && url.search === target.search;
    } catch {
      return false;
    }
  });
}

function validateRedirectUris(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REDIRECT_URIS) {
    throw new ClientError('invalid_redirect_uri', `redirect_uris must list 1 to ${MAX_REDIRECT_URIS} URIs`);
  }
  for (const uri of value) {
    if (!isAllowedRedirectUri(uri)) {
      throw new ClientError('invalid_redirect_uri', `redirect URI not allowed: ${JSON.stringify(uri)}`);
    }
  }
  return [...new Set(value as string[])];
}

function validateClientName(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > MAX_CLIENT_NAME_LENGTH) {
    throw new ClientError('invalid_client_metadata', `client_name must be a string of at most ${MAX_CLIENT_NAME_LENGTH} characters`);
  }
  return value;
}

function validateGrantAndResponseTypes(body: Record<string, unknown>): void {
  const grants = body.grant_types ?? ['authorization_code'];
  if (!Array.isArray(grants) || grants.some(grant => grant !== 'authorization_code' && grant !== 'refresh_token')) {
    throw new ClientError('invalid_client_metadata', 'grant_types may only contain authorization_code and refresh_token');
  }
  const responses = body.response_types ?? ['code'];
  if (!Array.isArray(responses) || responses.some(type => type !== 'code')) {
    throw new ClientError('invalid_client_metadata', 'response_types may only contain code');
  }
}

/** RFC 7591 registration. Returns the registration response body. */
export function registerClient(store: AuthStore, body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ClientError('invalid_client_metadata', 'registration body must be a JSON object');
  }
  const metadata = body as Record<string, unknown>;
  if (store.clientCount() >= MAX_REGISTERED_CLIENTS) {
    throw new ClientError('invalid_client_metadata', 'client registration limit reached');
  }
  const redirectUris = validateRedirectUris(metadata.redirect_uris);
  const clientName = validateClientName(metadata.client_name);
  validateGrantAndResponseTypes(metadata);
  const method = metadata.token_endpoint_auth_method ?? 'none';
  if (method !== 'none' && method !== 'client_secret_post' && method !== 'client_secret_basic') {
    throw new ClientError('invalid_client_metadata', 'token_endpoint_auth_method must be none, client_secret_post or client_secret_basic');
  }

  const clientId = `dcr_${randomToken(18)}`;
  const secret = method === 'none' ? undefined : randomToken(32);
  const now = Math.floor(Date.now() / 1000);
  const client: RegisteredClient = {
    clientId,
    ...(clientName ? { clientName } : {}),
    redirectUris,
    authMethod: method,
    ...(secret ? { secretHash: hashToken(secret) } : {}),
    createdAt: now
  };
  store.addClient(client);
  return {
    client_id: clientId,
    client_id_issued_at: now,
    ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
    ...(clientName ? { client_name: clientName } : {}),
    redirect_uris: redirectUris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: method
  };
}

/** Whether a client_id is a Client ID Metadata Document URL. */
export function isCimdClientId(clientId: string): boolean {
  if (!clientId.startsWith('https://')) return false;
  try {
    const url = new URL(clientId);
    return url.pathname !== '/' && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

interface CachedDocument {
  client: ResolvedClient;
  expiresAt: number;
}

const MIN_CACHE_SECONDS = 60;
const MAX_CACHE_SECONDS = 24 * 3600;
const DEFAULT_CACHE_SECONDS = 300;
const MAX_CACHE_ENTRIES = 100;

function cacheSeconds(header: string | string[] | undefined): number {
  const value = Array.isArray(header) ? header.join(',') : header ?? '';
  if (/no-store|no-cache/i.test(value)) return MIN_CACHE_SECONDS;
  const match = /max-age=(\d+)/i.exec(value);
  const seconds = match ? Number(match[1]) : DEFAULT_CACHE_SECONDS;
  return Math.min(MAX_CACHE_SECONDS, Math.max(MIN_CACHE_SECONDS, seconds));
}

/**
 * Fetches, validates and caches Client ID Metadata Documents
 * (draft-ietf-oauth-client-id-metadata-document, MCP 2025-11-25+).
 */
export class CimdResolver {
  private readonly cache = new Map<string, CachedDocument>();

  constructor(private readonly fetchOptions: SafeFetchOptions = {}) {}

  async resolve(clientId: string): Promise<ResolvedClient> {
    const cached = this.cache.get(clientId);
    if (cached && cached.expiresAt > Date.now()) return cached.client;

    let response;
    try {
      response = await safeFetch(clientId, this.fetchOptions);
    } catch (error) {
      const reason = error instanceof SafeFetchError ? error.message : 'fetch failed';
      throw new ClientError('invalid_client', `cannot fetch client metadata document: ${reason}`);
    }
    if (response.status !== 200) {
      throw new ClientError('invalid_client', `client metadata document answered HTTP ${response.status}`);
    }
    let document: Record<string, unknown>;
    try {
      const parsed = JSON.parse(response.body) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      document = parsed as Record<string, unknown>;
    } catch {
      throw new ClientError('invalid_client', 'client metadata document is not a JSON object');
    }
    if (document.client_id !== clientId) {
      throw new ClientError('invalid_client', 'client metadata document client_id does not match its URL');
    }
    const method = document.token_endpoint_auth_method ?? 'none';
    if (method !== 'none') {
      throw new ClientError('invalid_client', 'only public clients (token_endpoint_auth_method "none") are supported for metadata documents');
    }
    if (document.client_secret !== undefined) {
      throw new ClientError('invalid_client', 'client metadata document must not contain a client_secret');
    }
    let redirectUris: string[];
    let clientName: string | undefined;
    try {
      redirectUris = validateRedirectUris(document.redirect_uris);
      clientName = validateClientName(document.client_name);
      validateGrantAndResponseTypes(document);
    } catch (error) {
      throw new ClientError('invalid_client', (error as Error).message);
    }

    const client: ResolvedClient = {
      clientId,
      ...(clientName ? { clientName } : {}),
      redirectUris,
      authMethod: 'none',
      kind: 'cimd'
    };
    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(clientId, { client, expiresAt: Date.now() + cacheSeconds(response.headers['cache-control']) * 1000 });
    return client;
  }
}

export async function resolveClient(store: AuthStore, cimd: CimdResolver, clientId: unknown): Promise<ResolvedClient> {
  if (typeof clientId !== 'string' || clientId.length === 0 || clientId.length > MAX_URI_LENGTH) {
    throw new ClientError('invalid_client', 'missing or invalid client_id');
  }
  if (isCimdClientId(clientId)) return cimd.resolve(clientId);
  const registered = store.getClient(clientId);
  if (!registered) throw new ClientError('invalid_client', 'unknown client_id');
  return { ...registered, kind: 'dcr' };
}

/** Checks the client's credentials at the token endpoint. */
export function authenticateClient(client: ResolvedClient, presentedSecret: string | undefined): boolean {
  // Public clients prove possession through PKCE; a stray secret is ignored.
  if (client.authMethod === 'none') return true;
  if (!client.secretHash || !presentedSecret) return false;
  return constantTimeEqual(hashToken(presentedSecret), client.secretHash);
}
