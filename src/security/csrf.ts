/**
 * CSRF protection using double-submit cookie pattern.
 *
 * A random token is set in a non-HttpOnly cookie (readable by JS).
 * State-changing requests must include it in the X-CSRF-Token header.
 * The server compares the header value against the cookie value.
 */

import { randomBytes } from "node:crypto";
import type { Context, Next } from "hono";
import { getCookie, setCookie } from "hono/cookie";

const COOKIE_NAME = "aionima_csrf";
const HEADER_NAME = "x-csrf-token";

export function csrfMiddleware() {
  return async (c: Context, next: Next) => {
    // Ensure a CSRF cookie is always present
    let token = getCookie(c, COOKIE_NAME);
    if (!token) {
      token = randomBytes(32).toString("hex");
      setCookie(c, COOKIE_NAME, token, {
        path: "/",
        httpOnly: false, // JS needs to read this
        secure: process.env.NODE_ENV === "production",
        sameSite: "Lax",
        maxAge: 60 * 60 * 24, // 24h
      });
    }

    // Safe methods don't need CSRF validation
    const method = c.req.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      return next();
    }

    // In local mode, private-network auto-auth requests skip CSRF
    // (the network identity already proves ownership)
    const identity = c.get("identity") as { source?: string; isOwner?: boolean } | undefined;
    if (identity?.source === "private-network" && identity?.isOwner) {
      return next();
    }

    const headerToken = c.req.header(HEADER_NAME);

    if (!headerToken || headerToken !== token) {
      return c.json({ error: "CSRF token mismatch" }, 403);
    }

    return next();
  };
}
