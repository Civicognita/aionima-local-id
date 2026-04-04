/**
 * In-memory sliding-window rate limiter.
 *
 * Tracks request counts per IP within a time window.
 * Returns 429 Too Many Requests when limit is exceeded.
 */

import type { Context, Next } from "hono";

interface WindowEntry {
  count: number;
  resetAt: number;
}

export function rateLimit(opts: { windowMs: number; max: number; keyPrefix?: string }) {
  const store = new Map<string, WindowEntry>();
  const { windowMs, max, keyPrefix = "" } = opts;

  // Periodic cleanup every 60s to prevent memory leak
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (entry.resetAt <= now) {
        store.delete(key);
      }
    }
  }, 60_000).unref();

  return async (c: Context, next: Next) => {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim()
      ?? c.req.header("x-real-ip")
      ?? "unknown";

    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();

    let entry = store.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      store.set(key, entry);
    }

    entry.count++;

    c.header("X-RateLimit-Limit", String(max));
    c.header("X-RateLimit-Remaining", String(Math.max(0, max - entry.count)));
    c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      c.header("Retry-After", String(retryAfter));
      return c.json({ error: "Too many requests. Try again later." }, 429);
    }

    return next();
  };
}
