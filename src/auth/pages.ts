import type { Response } from 'express';

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLE = `
  :root { color-scheme: light dark; --bg: #f7f7f8; --fg: #1d1d1f; --card: #fff; --muted: #5f6368; --accent: #6965db; --border: #d9d9de; }
  @media (prefers-color-scheme: dark) { :root { --bg: #121214; --fg: #ececf1; --card: #1e1e22; --muted: #a0a0aa; --accent: #a8a5ff; --border: #34343a; } }
  body { margin: 0; font: 16px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--fg); }
  main { max-width: 32rem; margin: 10vh auto; padding: 0 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }
  h1 { font-size: 1.25rem; margin: 0 0 12px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 16px 0; }
  dt { color: var(--muted); } dd { margin: 0; overflow-wrap: anywhere; }
  .note { color: var(--muted); font-size: .9rem; }
  .actions { display: flex; gap: 12px; margin-top: 20px; }
  button { font: inherit; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--fg); cursor: pointer; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
`;

/** Headers for every HTML page the auth server renders. */
function securityHeaders(res: Response): void {
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  // Not no-referrer: that makes browsers send `Origin: null` on the consent
  // form POST, which the CSRF check would then reject.
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main><div class="card">${body}</div></main></body></html>`;
}

export function sendErrorPage(res: Response, status: number, title: string, message: string): void {
  securityHeaders(res);
  res.status(status).type('html').send(page(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`));
}

export interface ConsentView {
  clientName?: string;
  clientId: string;
  clientKind: 'dcr' | 'cimd';
  redirectUri: string;
  scope: string;
  login: string;
  ticket: string;
}

export function sendConsentPage(res: Response, view: ConsentView): void {
  securityHeaders(res);
  const redirectHost = new URL(view.redirectUri).host;
  const nameNote = view.clientKind === 'cimd'
    ? `The client is identified by a metadata document hosted at ${new URL(view.clientId).host}.`
    : 'The client registered itself; its name is self-asserted and not verified.';
  const body = `
    <h1>Allow access to your whiteboard?</h1>
    <p>Signed in with GitHub as <strong>${escapeHtml(view.login)}</strong>.</p>
    <dl>
      <dt>Client</dt><dd>${escapeHtml(view.clientName ?? '(unnamed client)')}</dd>
      <dt>Client ID</dt><dd><code>${escapeHtml(view.clientId)}</code></dd>
      <dt>Redirects to</dt><dd><strong>${escapeHtml(redirectHost)}</strong></dd>
      <dt>Access</dt><dd>${escapeHtml(view.scope)}: read and change every element on the canvas</dd>
    </dl>
    <p class="note">${escapeHtml(nameNote)} Only approve if you started this connection yourself.</p>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="ticket" value="${escapeHtml(view.ticket)}">
      <div class="actions">
        <button class="primary" type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>`;
  res.status(200).type('html').send(page('Authorize access', body));
}
