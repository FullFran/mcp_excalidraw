import type { RequestHandler } from 'express';

/**
 * Fixed-window, in-memory rate limiter keyed by client IP (`req.ip`, which
 * honours `TRUST_PROXY`). Good enough for a single-process, single-user
 * server; it resets on restart and is not shared between processes.
 */
export function rateLimit(options: { windowMs: number; max: number; name: string }): RequestHandler {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (req, res, next) => {
    const now = Date.now();
    if (hits.size > 10000) {
      for (const [key, entry] of hits) if (entry.resetAt <= now) hits.delete(key);
    }
    const key = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + options.windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > options.max) {
      res.setHeader('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      res.status(429).json({ error: 'rate_limited', error_description: `Too many ${options.name} requests; retry later.` });
      return;
    }
    next();
  };
}
