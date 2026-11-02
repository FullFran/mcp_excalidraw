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
  .user-code { display: block; font: 600 2rem/1.2 ui-monospace, monospace; letter-spacing: .12em; text-align: center; margin: 16px 0; padding: 12px; border: 1px dashed var(--border); border-radius: 8px; }
  .warning { border-left: 4px solid #d93025; padding: 8px 12px; background: color-mix(in srgb, #d93025 10%, transparent); border-radius: 4px; }
  a { color: var(--accent); }
`;

const BASE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

/** Headers for every HTML page the auth server renders. */
function securityHeaders(res: Response, extraCsp = ''): void {
  res.setHeader('Content-Security-Policy', `${BASE_CSP}${extraCsp}`);
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

export function sendErrorPage(res: Response, status: number, title: string, message: string, retryPath?: string): void {
  securityHeaders(res);
  const retry = retryPath ? `<p><a href="${escapeHtml(retryPath)}">Start the sign-in again</a></p>` : '';
  res.status(status).type('html').send(page(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${retry}`));
}

/** First step: a same-origin POST starts the GitHub device flow. */
export function sendLoginPage(res: Response, returnTo: string): void {
  securityHeaders(res);
  const body = `
    <h1>Sign in to the whiteboard</h1>
    <p>Sign in with your GitHub account. You will get a short code to enter on GitHub.</p>
    <form method="post" action="/oauth/login">
      <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
      <div class="actions"><button class="primary" type="submit">Sign in with GitHub</button></div>
    </form>`;
  res.status(200).type('html').send(page('Sign in', body));
}

export interface DeviceView {
  userCode: string;
  verificationUri: string;
  appName?: string;
  intervalSeconds: number;
  expiresAt: number;
}

/**
 * Second step: the code to enter on GitHub. The page polls this server with
 * a same-origin script (no secrets in it: the binding cookie is HttpOnly).
 */
export function sendDevicePage(res: Response, view: DeviceView): void {
  securityHeaders(res, "; script-src 'self'; connect-src 'self'");
  const app = view.appName
    ? `GitHub will ask you to authorize <strong>${escapeHtml(view.appName)}</strong>. If it names another app, stop.`
    : 'GitHub will ask you to authorize the OAuth app created for this whiteboard. If it names an app you do not recognise, stop.';
  const minutes = Math.max(1, Math.round((view.expiresAt - Date.now()) / 60000));
  const body = `
    <h1>Enter this code on GitHub</h1>
    <p class="warning"><strong>Only enter this code if you started this sign-in on this screen just now.</strong> Nobody from this whiteboard will ever send you a code to enter.</p>
    <code class="user-code">${escapeHtml(view.userCode)}</code>
    <p>Open <a href="${escapeHtml(view.verificationUri)}" target="_blank" rel="noopener noreferrer">${escapeHtml(view.verificationUri)}</a> and type the code. ${app}</p>
    <p class="note" id="device-status" data-interval="${view.intervalSeconds}">Waiting for GitHub… This code expires in about ${minutes} minute${minutes === 1 ? '' : 's'}. Keep this page open; it continues by itself.</p>
    <form method="post" action="/oauth/device/poll">
      <div class="actions"><button type="submit">I have entered the code</button></div>
    </form>
    <script src="/oauth/device.js" defer></script>`;
  res.status(200).type('html').send(page('Enter the code on GitHub', body));
}

/** Polls `/oauth/device/poll` at the server-given interval, then moves on. */
export const DEVICE_SCRIPT = `(() => {
  const status = document.getElementById('device-status');
  let interval = Math.max(1, Number(status && status.dataset.interval) || 5);
  const poll = async () => {
    let result;
    try {
      const response = await fetch('/oauth/device/poll', { method: 'POST', credentials: 'same-origin', headers: { accept: 'application/json' } });
      result = await response.json();
    } catch {
      result = { status: 'pending' };
    }
    if (result && result.status === 'complete' && typeof result.redirect === 'string' && result.redirect.startsWith('/') && !result.redirect.startsWith('//')) {
      window.location.assign(result.redirect);
      return;
    }
    if (!result || result.status !== 'pending') {
      window.location.assign('/oauth/device');
      return;
    }
    if (typeof result.interval === 'number' && result.interval > 0) interval = result.interval;
    setTimeout(poll, interval * 1000);
  };
  setTimeout(poll, interval * 1000);
})();
`;

export function sendDeviceScript(res: Response): void {
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).type('application/javascript').send(DEVICE_SCRIPT);
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
