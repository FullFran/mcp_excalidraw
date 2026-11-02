import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import https from 'node:https';
import type { LookupFunction } from 'node:net';

/**
 * Address ranges an outbound fetch of a client-supplied URL must never reach:
 * loopback, private, link-local, CGNAT, documentation, multicast, reserved,
 * and their IPv6 equivalents. IPv4-mapped IPv6 addresses are unwrapped and
 * checked as IPv4; IPv4-compatible ones (`::a.b.c.d`) are all refused.
 */
const BLOCKED = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) {
  BLOCKED.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  // ::/96 also covers the deprecated IPv4-compatible form (`::127.0.0.1`).
  ['::', 96], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as const) {
  BLOCKED.addSubnet(network, prefix, 'ipv6');
}

/** Returns true when the address is a public unicast address. */
export type AddressGuard = (address: string) => boolean;

export const publicAddressGuard: AddressGuard = address => {
  const family = isIP(address);
  if (family === 4) return !BLOCKED.check(address, 'ipv4');
  if (family === 6) {
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
    if (mapped) return !BLOCKED.check(mapped[1]!, 'ipv4');
    if (/^::ffff:/i.test(address)) return false;
    return !BLOCKED.check(address, 'ipv6');
  }
  return false;
};

export interface SafeFetchOptions {
  /** Which resolved addresses may be contacted. Defaults to public addresses only. */
  addressGuard?: AddressGuard;
  /** Extra trusted CA certificates (tests use a self-signed one). */
  ca?: string | Buffer;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface SafeFetchResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export class SafeFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafeFetchError';
  }
}

/**
 * GET an https URL supplied by a third party without letting it reach
 * internal services: https only, no credentials in the URL, every resolved
 * address must pass the guard and the connection is pinned to a checked
 * address (no DNS-rebinding window), no redirects, bounded time and size.
 */
export async function safeFetch(rawUrl: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const guard = options.addressGuard ?? publicAddressGuard;
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 64 * 1024;

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SafeFetchError('not an absolute URL');
  }
  if (url.protocol !== 'https:') throw new SafeFetchError('only https URLs are fetched');
  if (url.username || url.password) throw new SafeFetchError('URL must not carry credentials');

  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  let addresses: { address: string; family: number }[];
  if (isIP(hostname)) {
    addresses = [{ address: hostname, family: isIP(hostname) }];
  } else {
    try {
      addresses = await lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new SafeFetchError(`cannot resolve ${hostname}`);
    }
  }
  if (addresses.length === 0) throw new SafeFetchError(`cannot resolve ${hostname}`);
  const blocked = addresses.find(entry => !guard(entry.address));
  if (blocked) throw new SafeFetchError(`${hostname} resolves to a non-public address (${blocked.address})`);
  const pinned = addresses[0]!;

  const pinnedLookup: LookupFunction = (_host, lookupOptions, callback) => {
    if ((lookupOptions as { all?: boolean }).all) {
      (callback as unknown as (err: null, addrs: { address: string; family: number }[]) => void)(null, [pinned]);
    } else {
      callback(null, pinned.address, pinned.family);
    }
  };

  return new Promise<SafeFetchResult>((resolve, reject) => {
    const request = https.request(url, {
      method: 'GET',
      lookup: pinnedLookup,
      // No pooled sockets: each fetch connects to the address checked above.
      agent: false,
      headers: { accept: 'application/json', 'user-agent': 'mcp-excalidraw-auth/1' },
      ...(options.ca ? { ca: options.ca } : {}),
      timeout: timeoutMs
    }, response => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBytes) {
          request.destroy(new SafeFetchError(`response larger than ${maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8')
      }));
      response.on('error', reject);
    });
    const deadline = setTimeout(() => request.destroy(new SafeFetchError(`timed out after ${timeoutMs}ms`)), timeoutMs);
    request.on('close', () => clearTimeout(deadline));
    request.on('timeout', () => request.destroy(new SafeFetchError(`timed out after ${timeoutMs}ms`)));
    request.on('error', error => reject(error instanceof SafeFetchError ? error : new SafeFetchError(error.message)));
    request.end();
  });
}
