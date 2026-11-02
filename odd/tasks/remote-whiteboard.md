Objective: turn the mcp_excalidraw fork into a remote, authenticated whiteboard MCP that Fran's agents and ChatGPT can use, and where Fran can write by hand.
Branch: `feat/remote-whiteboard` (work units merged to `main` of FullFran/mcp_excalidraw). Delivery: one work-unit commit per task; push and PRs are Fran's call. Runner: `npm test` (+ new focused scripts under `scripts/`).

## Specs

- S1 (fork + local): "podriamos hacer un fork y extenderlo" / "inicializalo en mi maquina en la carpeta fullfran porque es un proyecto personal". Fork at FullFran/mcp_excalidraw, clone at `~/fullfran/mcp_excalidraw`, `upstream` remote kept for syncing.
- S2 (MCP 2026): "actualizar a los standares de mcp de 2026". MCP over Streamable HTTP at `/mcp`, spec 2026-07-28, and still accepting 2025-11-25 clients (ChatGPT's version is unconfirmed). stdio unchanged. Issues #1, #2.
- S3 (auth): "hacer autenticacion". OAuth 2.1 for `/mcp` (RFC 9728 resource metadata, PKCE, RFC 9207 `iss`, CIMD plus DCR for compatibility), login delegated to GitHub with only allowed accounts, and the same session protecting the canvas UI, REST API and WebSocket. Local 127.0.0.1 use stays zero-config. Issues #3, #4, #5.
- S4 (boards): parent proposal accepted with "me gusta mucho, hazlo!": several named boards (doctorado, ideas...) instead of one canvas. Issue #6.
- S5 (VPS + clients): "publicarlo en mi vps y poder conectar el mcp en mis agentes y en chat gpt y demas". Docker + HTTPS on the VPS; connect Claude Code, Codex, ChatGPT and the iPad. Remote work needs Fran's explicit authorization of host, domain and access first. Issues #7, #8.
- S6 (tracking): "deja ticket en notion. y organiza issues y milestones". Notion ticket in Entradas · UMBRAL; GitHub milestones M1-M4 with issues #1-#8.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T0 | S1, S6 | inline | done | fork + clone + upstream remote; milestones 1-4, issues #1-#8; Notion ticket 40c21333-8135-81f3-b292-f1b2b9e2fb4c; baseline `npm test` exit 0 at 66b768b |
| T1 | S2 | delegated (writer trigger b: long-session context backstop) | done (uncommitted) | RED: `npm run test:mcp-http` 7/9 failing (404 on /mcp); GREEN: 9/9; `npm run test:mcp` 5/5; `npm test` exit 0; `npm run type-check` exit 0 |
| T2 | S3 | pending | pending | |
| T3 | S4 | pending | pending | |
| T4 | S5 | pending | blocked: needs VPS authorization | |

## Log

- L1 (2026-11-02, Fran): "joder me gusta mucho, el mcp de excalidraw que comentas, podriamos hacer un fork y extenderlo, hacer autenticacion y actualizar a los standares de mcp de 2026, publicarlo en mi vps y poder conectar el mcp en mis agentes y en chat gpt y demas"
- L2 (2026-11-02, Fran): "me gusta mucho, hazlo! y deja ticket en notion. y organiza issues y milestones. inicializalo en mi maquina en la carpeta fullfran porque es un proyecto personal"
- L3: upstream 2.1.2 (66b768b) already uses `@modelcontextprotocol/server` 2.0.0 but only over stdio; the canvas server (Express + WS, `src/server.ts`) has no authentication. Spec 2026-07-28: stateless (no initialize, no Mcp-Session-Id), DCR deprecated in favour of CIMD, RFC 9207 `iss`. ChatGPT needs a public HTTPS `/mcp` with OAuth and allowlisted redirect `https://chatgpt.com/connector_platform_oauth_redirect`.
- L4: Why this repo and not devdotfast/whiteboard: the latter is a code-review canvas where only the agent draws; Fran wants to write by hand on a shared board.
- L5 (2026-11-02, T1): `/mcp` uses the SDK's own `createMcpHandler` (`@modelcontextprotocol/server` 2.0.0; no `@modelcontextprotocol/node`/`express` adapter installed, so `src/core/mcp-http.ts` bridges Express to the web-standard Request/Response). 2025-era clients are served by the SDK's stateless legacy fallback: `initialize` works but no `Mcp-Session-Id` is issued and GET/DELETE answer 405. In-process tools are repointed at the server's own listener (`useInProcessCanvasUrl`) so HTTP tool calls hit the same canvas as REST. Host/Origin guard (SDK helpers) only on loopback binds, allowing the `PUBLIC_BASE_URL` hostname; `TRUST_PROXY` off by default. Auth seam for T2: `createMcpHttpRouter({ authMiddleware })`, principal via `res.locals.mcpAuthInfo`. Differential vs a7a6894: `--help`, stdio wire test, and REST responses identical; `/mcp` 404 -> 405 on GET.
