import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { resolvePublicBaseUrl } from '../core/config.js';
import { isLoopbackBindHost } from '../core/mcp-http.js';

/** The single OAuth scope this server issues and requires. */
export const WHITEBOARD_SCOPE = 'whiteboard';

/** Smallest accepted signing secret (characters of the env/file value). */
const MIN_SECRET_LENGTH = 32;
const GITHUB_LOGIN_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,38})$/i;
const LOOPBACK_URL_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

export class AuthConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthConfigError';
  }
}

export interface AuthOffConfig {
  mode: 'off';
  /** True when auth was switched off explicitly on a non-loopback bind. */
  insecure: boolean;
}

export interface AuthOnConfig {
  mode: 'oauth';
  /** Authorization server issuer and public origin, e.g. `https://board.example.com`. */
  issuer: string;
  /** Protected resource identifier: `${issuer}/mcp`. Access tokens are bound to it. */
  resource: string;
  /** Whether cookies get `Secure` (the public base URL is https). */
  secureCookies: boolean;
  github: {
    clientId: string;
    clientSecret: string;
    oauthBaseUrl: string;
    apiBaseUrl: string;
  };
  /** Lower-cased GitHub logins allowed to get a session. */
  allowedLogins: Set<string>;
  /** Raw signing secret; keys are derived from it per purpose. */
  secret: Buffer;
  /** JSON file holding hashed tokens and registered clients (0600). */
  storePath: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  sessionTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}

export type AuthConfig = AuthOffConfig | AuthOnConfig;

type Env = Record<string, string | undefined>;

function readSecret(env: Env, name: string, missing: string[]): string | undefined {
  const direct = env[name]?.trim();
  const filePath = env[`${name}_FILE`]?.trim();
  if (direct && filePath) {
    throw new AuthConfigError(`Set only one of ${name} and ${name}_FILE.`);
  }
  if (direct) return direct;
  if (filePath) {
    try {
      const value = readFileSync(filePath, 'utf8').trim();
      if (value) return value;
    } catch (error) {
      throw new AuthConfigError(`Cannot read ${name}_FILE (${filePath}): ${(error as Error).message}`);
    }
    throw new AuthConfigError(`${name}_FILE (${filePath}) is empty.`);
  }
  missing.push(`${name} (or ${name}_FILE)`);
  return undefined;
}

function readTtl(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) throw new AuthConfigError(`${name} must be a whole number of seconds, got ${JSON.stringify(raw)}.`);
  const value = Number(raw);
  if (value < min || value > max) throw new AuthConfigError(`${name} must be between ${min} and ${max}, got ${value}.`);
  return value;
}

function normalizeBaseUrl(name: string, raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AuthConfigError(`${name} must be an absolute URL, got ${JSON.stringify(raw)}.`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new AuthConfigError(`${name} must use http or https, got ${JSON.stringify(raw)}.`);
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
}

/**
 * Decides whether authentication is on, from the bind host and env.
 *
 * - Loopback bind and no `AUTH_MODE`: auth off (zero-config local use).
 * - Non-loopback bind, or `AUTH_MODE=oauth`: auth on; every required variable
 *   must be present or this throws naming each missing one.
 * - `AUTH_MODE=off` on a non-loopback bind: refused unless
 *   `ALLOW_INSECURE_NO_AUTH=true`.
 */
export function resolveAuthConfig(bindHost: string, env: Env = process.env): AuthConfig {
  const mode = env.AUTH_MODE?.trim().toLowerCase() ?? '';
  if (mode !== '' && mode !== 'off' && mode !== 'oauth') {
    throw new AuthConfigError(`AUTH_MODE must be "off" or "oauth", got ${JSON.stringify(env.AUTH_MODE)}.`);
  }
  const loopback = isLoopbackBindHost(bindHost);

  if (mode === 'off' || (mode === '' && loopback)) {
    if (!loopback) {
      if (env.ALLOW_INSECURE_NO_AUTH?.trim() !== 'true') {
        throw new AuthConfigError(
          `Refusing to start without authentication on non-loopback HOST=${bindHost}: AUTH_MODE=off ` +
          'exposes the canvas, REST API, WebSocket and /mcp to anyone who can reach this address. ' +
          'Set ALLOW_INSECURE_NO_AUTH=true only if another layer authenticates every request.'
        );
      }
      return { mode: 'off', insecure: true };
    }
    return { mode: 'off', insecure: false };
  }

  const missing: string[] = [];
  const reason = mode === 'oauth' ? 'AUTH_MODE=oauth' : `HOST=${bindHost} is not loopback`;

  let issuer: string | undefined;
  try {
    issuer = resolvePublicBaseUrl(env.PUBLIC_BASE_URL);
  } catch (error) {
    throw new AuthConfigError((error as Error).message);
  }
  if (!issuer) missing.push('PUBLIC_BASE_URL');

  const clientId = env.GITHUB_CLIENT_ID?.trim();
  if (!clientId) missing.push('GITHUB_CLIENT_ID');
  const clientSecret = readSecret(env, 'GITHUB_CLIENT_SECRET', missing);
  const secret = readSecret(env, 'AUTH_SECRET', missing);

  const loginsRaw = env.ALLOWED_GITHUB_LOGINS?.trim();
  if (!loginsRaw) missing.push('ALLOWED_GITHUB_LOGINS');

  const dataDir = env.EXCALIDRAW_DATA_DIR?.trim();
  if (!dataDir) missing.push('EXCALIDRAW_DATA_DIR');

  if (missing.length > 0) {
    throw new AuthConfigError(
      `Authentication is required (${reason}) but these variables are missing: ${missing.join(', ')}. ` +
      'See docs/auth.md.'
    );
  }

  const url = new URL(issuer!);
  if (url.pathname !== '/') {
    throw new AuthConfigError(
      `PUBLIC_BASE_URL must be an origin without a path when authentication is on, got ${JSON.stringify(issuer)}.`
    );
  }
  if (url.protocol !== 'https:' && !LOOPBACK_URL_HOSTS.has(url.hostname)) {
    throw new AuthConfigError(
      `PUBLIC_BASE_URL must use https when authentication is on (http is only accepted for loopback hosts), got ${JSON.stringify(issuer)}.`
    );
  }
  if (secret!.length < MIN_SECRET_LENGTH) {
    throw new AuthConfigError(`AUTH_SECRET must be at least ${MIN_SECRET_LENGTH} characters (use e.g. \`openssl rand -base64 48\`).`);
  }

  const allowedLogins = new Set<string>();
  for (const entry of loginsRaw!.split(',')) {
    const login = entry.trim();
    if (!login) continue;
    if (!GITHUB_LOGIN_PATTERN.test(login)) {
      throw new AuthConfigError(`ALLOWED_GITHUB_LOGINS contains an invalid GitHub login: ${JSON.stringify(login)}.`);
    }
    allowedLogins.add(login.toLowerCase());
  }
  if (allowedLogins.size === 0) {
    throw new AuthConfigError('ALLOWED_GITHUB_LOGINS must list at least one GitHub login.');
  }

  const base = url.origin;
  return {
    mode: 'oauth',
    issuer: base,
    resource: `${base}/mcp`,
    secureCookies: url.protocol === 'https:',
    github: {
      clientId: clientId!,
      clientSecret: clientSecret!,
      oauthBaseUrl: normalizeBaseUrl('GITHUB_OAUTH_BASE_URL', env.GITHUB_OAUTH_BASE_URL?.trim() || 'https://github.com'),
      apiBaseUrl: normalizeBaseUrl('GITHUB_API_BASE_URL', env.GITHUB_API_BASE_URL?.trim() || 'https://api.github.com')
    },
    allowedLogins,
    secret: Buffer.from(secret!, 'utf8'),
    storePath: join(resolve(dataDir!), 'auth-store.json'),
    accessTokenTtlSeconds: readTtl(env, 'AUTH_ACCESS_TOKEN_TTL_SECONDS', 3600, 1, 86400),
    refreshTokenTtlSeconds: readTtl(env, 'AUTH_REFRESH_TOKEN_TTL_SECONDS', 30 * 86400, 60, 90 * 86400),
    sessionTtlSeconds: readTtl(env, 'AUTH_SESSION_TTL_SECONDS', 7 * 86400, 60, 30 * 86400),
    authorizationCodeTtlSeconds: 60
  };
}
