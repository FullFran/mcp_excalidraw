# Authentication

The canvas server can protect everything it serves — the MCP endpoint (`/mcp`), the canvas page and its assets, the REST API (`/api/*`) and the WebSocket — with OAuth 2.1. You sign in with GitHub, and only the GitHub accounts you list get in. There are no local passwords.

## When authentication is on

| Bind (`HOST`) | `AUTH_MODE` | Result |
|---|---|---|
| loopback (`127.0.0.1`, the default; `localhost`, `::1`) | unset | **Off.** Local stdio, CLI and `127.0.0.1` use stay zero-config, exactly as before. |
| any | `oauth` | **On.** Startup fails if a required variable is missing, and the error names it. |
| non-loopback (`0.0.0.0`, `::`, a LAN address) | unset | **On**, same rules as `oauth`. |
| non-loopback | `off` | **Refused** unless `ALLOW_INSECURE_NO_AUTH=true` is also set. |

`ALLOW_INSECURE_NO_AUTH=true` is dangerous: anyone who can reach the address can read and change the canvas and call every MCP tool. Use it only when another layer (a VPN-only network, an authenticating proxy) checks every request.

On a loopback bind, GitHub or auth variables without `AUTH_MODE=oauth` are ignored, so a stray `GITHUB_CLIENT_ID` in your shell never locks you out of a local canvas.

> **Docker:** the canvas image sets `HOST=0.0.0.0`, so it now needs either the variables below or `AUTH_MODE=off` with `ALLOW_INSECURE_NO_AUTH=true` (for example when only `-p 127.0.0.1:3000:3000` publishes the port).

## Environment variables

| Variable | Required when on | Meaning |
|---|---|---|
| `AUTH_MODE` | – | `oauth` or `off`. See the table above. |
| `PUBLIC_BASE_URL` | yes | Public origin, e.g. `https://board.example.com`. Must be `https` (plain `http` only for `127.0.0.1`/`localhost`) and must not have a path. It is the OAuth issuer; the protected resource is `${PUBLIC_BASE_URL}/mcp`. |
| `GITHUB_CLIENT_ID` | yes | Client ID of your GitHub OAuth app. |
| `GITHUB_CLIENT_SECRET` or `GITHUB_CLIENT_SECRET_FILE` | yes | Its client secret, or a file containing it. |
| `ALLOWED_GITHUB_LOGINS` | yes | Comma-separated GitHub logins allowed to sign in, case-insensitive, e.g. `FullFran`. There is no default. |
| `AUTH_SECRET` or `AUTH_SECRET_FILE` | yes | At least 32 characters; signs session cookies, the login `state` cookie and consent forms. Generate it with `openssl rand -base64 48`. Changing it signs everyone out. |
| `EXCALIDRAW_DATA_DIR` | yes | Data directory. Tokens and registered clients are kept in `auth-store.json` there (mode `0600`). It also turns on durable canvas state. |
| `TRUST_PROXY` | behind a proxy | Set it (e.g. `loopback`) when a reverse proxy you control terminates TLS, so rate limits see client IPs. |
| `AUTH_ACCESS_TOKEN_TTL_SECONDS` | no | Access token lifetime. Default `3600` (1 h), 1–86400. |
| `AUTH_REFRESH_TOKEN_TTL_SECONDS` | no | Refresh token lifetime. Default 30 days. |
| `AUTH_SESSION_TTL_SECONDS` | no | Browser session lifetime. Default 7 days. |
| `GITHUB_OAUTH_BASE_URL` / `GITHUB_API_BASE_URL` | no | Override `https://github.com` / `https://api.github.com` (GitHub Enterprise, or a fake GitHub in tests). |

## Create the GitHub OAuth app

1. GitHub → Settings → Developer settings → **OAuth Apps** → **New OAuth App**.
2. **Homepage URL:** your `PUBLIC_BASE_URL`, e.g. `https://board.example.com`.
3. **Authorization callback URL:** `${PUBLIC_BASE_URL}/oauth/github/callback`, e.g. `https://board.example.com/oauth/github/callback`.
4. Create it, then **Generate a new client secret**. Put the client ID in `GITHUB_CLIENT_ID` and the secret in `GITHUB_CLIENT_SECRET` (or a `0600` file named by `GITHUB_CLIENT_SECRET_FILE`).

The app asks GitHub for no scopes: the server only reads the login of whoever signed in, and throws GitHub's token away right after.

Example:

```bash
HOST=127.0.0.1 PORT=3000 TRUST_PROXY=loopback \
PUBLIC_BASE_URL=https://board.example.com \
AUTH_MODE=oauth \
GITHUB_CLIENT_ID=Iv1.xxxxx GITHUB_CLIENT_SECRET_FILE=/etc/excalidraw/github-secret \
ALLOWED_GITHUB_LOGINS=FullFran \
AUTH_SECRET_FILE=/etc/excalidraw/auth-secret \
EXCALIDRAW_DATA_DIR=/var/lib/excalidraw \
node dist/server.js
```

## What is protected, and how

| Surface | Without credentials | Accepted credentials |
|---|---|---|
| `/mcp` | `401` with `WWW-Authenticate: Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource", scope="whiteboard"` | `Authorization: Bearer <access token>` for resource `${PUBLIC_BASE_URL}/mcp` with scope `whiteboard` |
| canvas page, static files | `302` to `/oauth/login` | session cookie |
| `/api/*` | `401` | session cookie, or a bearer access token. Writes with the cookie must come from `PUBLIC_BASE_URL` (`Origin`, or `Referer` when there is no `Origin`), otherwise `403`. |
| WebSocket | `401` | bearer access token, or the session cookie with `Origin` equal to `PUBLIC_BASE_URL` (any other Origin: `403`) |
| `/health` | open | answers only `{"status":"healthy","service":"mcp-excalidraw-canvas"}` — no counts, no pid |

MCP tools called over `/mcp` reach the REST API of the same process with a per-process random credential that never leaves the process.

## Endpoints

| Path | Purpose |
|---|---|
| `/.well-known/oauth-protected-resource` (also `/…/mcp`) | RFC 9728 protected resource metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata |
| `/oauth/register` | RFC 7591 Dynamic Client Registration (public or `client_secret_post`/`client_secret_basic` clients) |
| `/oauth/authorize` | Authorization code + PKCE `S256` only. Shows a consent page with the client's name, ID and redirect host. |
| `/oauth/token` | `authorization_code` and `refresh_token` grants |
| `/oauth/login`, `/oauth/github/callback` | GitHub sign-in |
| `/oauth/logout` | `POST` from the same origin clears the session cookie |

Protocol details:

- **PKCE** is mandatory and only `S256` is accepted; `plain` or a missing challenge is rejected with `invalid_request`.
- **RFC 9207:** every authorization response, success or error, carries `iss=${PUBLIC_BASE_URL}`.
- **RFC 8707:** `resource` is optional; when given it must be `${PUBLIC_BASE_URL}/mcp` (`invalid_target` otherwise). Every token is bound to that resource and checked on every request.
- **Codes** live 60 s, are single use, and are burnt on the first presentation whatever the outcome. Presenting a used code again revokes the tokens it produced.
- **Refresh tokens rotate.** Each one works once; reusing an old one revokes its whole family (every access and refresh token descending from the same authorization code).
- **Clients** are either a Client ID Metadata Document URL (the 2025-11-25 / 2026-07-28 way; `client_id` is an `https` URL with a path whose JSON document lists `redirect_uris`) or a client registered through `/oauth/register`. Metadata documents are fetched only over `https`, only from public IP addresses (loopback, private, link-local, CGNAT, multicast and IPv4-mapped forms are refused, and the connection is pinned to the checked address), without redirects, within 5 s and 64 KiB, and cached for its `Cache-Control: max-age` between 1 minute and 24 hours. Only public clients (`token_endpoint_auth_method: "none"`) are accepted from a document.
- **Redirect URIs** must be registered exactly. Allowed forms: any `https` URI (including `https://chatgpt.com/connector_platform_oauth_redirect`) and `http://127.0.0.1`, `http://localhost` or `http://[::1]` for CLI agents. For those loopback URIs the port may differ from the registered one (RFC 8252 §7.3); scheme, host, path and query must match.
- **Storage:** access and refresh tokens are 256-bit random strings; only their SHA-256 hashes are written, with client secrets also hashed, to `auth-store.json` (`0600`, written atomically). Authorization codes and consent state are kept in memory and lost on restart.
- **Rate limits** (per client IP, in memory): `/oauth/token` 60/min, `/oauth/register` 10/min, login and callback 20/min, `/oauth/authorize` 60/min. DCR is capped at 200 registered clients.

## Connecting clients

In every case the client discovers the authorization server from the `401` on `/mcp`, opens a browser on `/oauth/authorize`, you sign in with GitHub (first time only, then the session cookie remembers you), and you approve on the consent page.

**ChatGPT** (connectors / developer mode): add a custom connector with the MCP server URL `https://board.example.com/mcp` and authentication **OAuth**. ChatGPT registers itself through `/oauth/register` with the redirect `https://chatgpt.com/connector_platform_oauth_redirect`.

**Claude Code:**

```bash
claude mcp add --transport http excalidraw https://board.example.com/mcp
# then, inside Claude Code: /mcp → excalidraw → Authenticate
```

**Codex CLI:**

```toml
# ~/.codex/config.toml
[mcp_servers.excalidraw]
url = "https://board.example.com/mcp"
```

```bash
codex mcp login excalidraw
```

Both CLIs use a loopback redirect (`http://localhost:<port>/…` or `http://127.0.0.1:<port>/…`), which is allowed.

**The canvas in a browser (or an iPad):** open `https://board.example.com/`. You are sent to GitHub, then back to the canvas.

Client flags change between versions; check each client's own documentation if a command above differs.

## Threat model

Defended against:

- **Anyone on the internet** reaching the server: every surface except `/health` and the OAuth endpoints needs a GitHub login from the allowlist or a token issued after one.
- **Other GitHub users:** they can complete GitHub's login, but get no session and no token.
- **Stolen or replayed codes:** PKCE `S256`, exact redirect matching, 60 s single-use codes, replay revokes the issued tokens.
- **Leaked refresh tokens:** rotation with family revocation on reuse; short-lived access tokens.
- **Token confusion:** tokens are bound to `${PUBLIC_BASE_URL}/mcp` and refused anywhere else; RFC 9207 `iss` lets clients detect mix-up attacks.
- **CSRF and cross-site WebSocket hijacking:** `SameSite=Lax` cookies, an `Origin` check on cookie-authenticated writes, the consent form and the WebSocket, a signed `state` cookie for the GitHub round trip, consent tickets bound to the session.
- **Clickjacking of the consent page:** `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- **SSRF through client metadata URLs:** https only, public addresses only, pinned connection, no redirects, size and time limits.
- **Store disclosure:** the store holds only hashes; a copy of it does not grant access.

Assumptions:

- TLS is terminated by a reverse proxy you control, and `PUBLIC_BASE_URL` is the URL people actually use. Set `TRUST_PROXY` only for that proxy.
- `AUTH_SECRET` and the GitHub client secret are kept private (file mode `0600` or a secrets manager).
- One process owns the data directory (the existing data-directory lock enforces this).

Out of scope:

- Users or roles beyond the allowlist: every allowed login has full access to the canvas.
- Revoking one client from a UI. To revoke everything, stop the server and delete `auth-store.json`; to sign every browser out, change `AUTH_SECRET`; to drop a person, remove their login from `ALLOWED_GITHUB_LOGINS` and restart (their sessions and tokens stop working).
- Token introspection and revocation endpoints (RFC 7662 / 7009), `private_key_jwt` clients, OpenID Connect.
- Rate limiting shared across processes, and protection against volumetric denial of service (use the proxy).
- The CLI (`excalidraw-canvas …`) and the stdio MCP server talking to a *remote* authenticated canvas: they send no token. Use `/mcp` for remote agents.
- `excalidraw-canvas stop` against an authenticated server, since `/health` no longer reports the pid: stop it with your process manager.
