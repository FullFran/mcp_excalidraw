import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** Opaque random token: 32 bytes of CSPRNG output, base64url. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Only this hash of a token is ever stored. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function isValidCodeChallenge(challenge: string): boolean {
  return PKCE_CHALLENGE_PATTERN.test(challenge);
}

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge. */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!PKCE_VERIFIER_PATTERN.test(verifier)) return false;
  const computed = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return constantTimeEqual(computed, challenge);
}

/**
 * HMAC-signed, expiring JSON values for cookies and form tickets. Each use
 * has its own purpose string, so a value signed for one purpose (say, the
 * GitHub `state` cookie) never verifies as another (the session cookie).
 */
export class Signer {
  private readonly key: Buffer;

  constructor(secret: Buffer) {
    this.key = createHmac('sha256', secret).update('mcp-excalidraw/signer/v1').digest();
  }

  private mac(purpose: string, data: string): string {
    return createHmac('sha256', this.key).update(`${purpose}\n${data}`).digest('base64url');
  }

  sign(purpose: string, payload: Record<string, unknown>, ttlSeconds: number): string {
    const body = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
    const data = Buffer.from(JSON.stringify(body), 'utf8').toString('base64url');
    return `${data}.${this.mac(purpose, data)}`;
  }

  verify<T extends Record<string, unknown>>(purpose: string, value: string | undefined): (T & { exp: number }) | null {
    if (!value) return null;
    const dot = value.indexOf('.');
    if (dot <= 0 || dot !== value.lastIndexOf('.')) return null;
    const data = value.slice(0, dot);
    const mac = value.slice(dot + 1);
    if (!constantTimeEqual(mac, this.mac(purpose, data))) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (!parsed || typeof parsed !== 'object') return null;
    const exp = (parsed as { exp?: unknown }).exp;
    if (typeof exp !== 'number' || exp <= Math.floor(Date.now() / 1000)) return null;
    return parsed as T & { exp: number };
  }
}
