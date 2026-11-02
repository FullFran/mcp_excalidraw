import type { AuthOnConfig } from './config.js';

const GITHUB_TIMEOUT_MS = 10000;

export class GitHubLoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitHubLoginError';
  }
}

/** URL to send the browser to for GitHub's own login + consent. */
export function githubAuthorizeUrl(config: AuthOnConfig, state: string, callbackUrl: string): string {
  const url = new URL(`${config.github.oauthBaseUrl}/login/oauth/authorize`);
  url.searchParams.set('client_id', config.github.clientId);
  url.searchParams.set('redirect_uri', callbackUrl);
  url.searchParams.set('state', state);
  // No scope: the public profile (login) is all this server needs.
  url.searchParams.set('scope', '');
  url.searchParams.set('allow_signup', 'false');
  return url.toString();
}

/**
 * Exchanges GitHub's authorization code and returns the authenticated login.
 * The GitHub token is used once to read `/user` and is never stored.
 */
export async function exchangeGitHubCode(config: AuthOnConfig, code: string, callbackUrl: string): Promise<string> {
  const tokenResponse = await fetch(`${config.github.oauthBaseUrl}/login/oauth/access_token`, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.github.clientId,
      client_secret: config.github.clientSecret,
      code,
      redirect_uri: callbackUrl
    }),
    redirect: 'error',
    signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS)
  }).catch(error => {
    throw new GitHubLoginError(`GitHub token exchange failed: ${(error as Error).message}`);
  });
  const tokenBody = await tokenResponse.json().catch(() => null) as { access_token?: unknown; error?: unknown } | null;
  if (!tokenResponse.ok || !tokenBody || typeof tokenBody.access_token !== 'string') {
    throw new GitHubLoginError(`GitHub token exchange was rejected${tokenBody?.error ? ` (${String(tokenBody.error)})` : ''}`);
  }

  const userResponse = await fetch(`${config.github.apiBaseUrl}/user`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${tokenBody.access_token}`,
      'user-agent': 'mcp-excalidraw-auth',
      'x-github-api-version': '2022-11-28'
    },
    redirect: 'error',
    signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS)
  }).catch(error => {
    throw new GitHubLoginError(`GitHub user lookup failed: ${(error as Error).message}`);
  });
  const user = await userResponse.json().catch(() => null) as { login?: unknown } | null;
  if (!userResponse.ok || !user || typeof user.login !== 'string' || user.login.length === 0) {
    throw new GitHubLoginError('GitHub user lookup returned no login');
  }
  return user.login;
}
