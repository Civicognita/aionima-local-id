import type { Context, Next } from "hono";
import { getCookie } from "hono/cookie";
import type { AppLucia } from "./lucia.js";

export type AuthEnv = {
  Variables: {
    user: {
      id: string;
      email: string;
      displayName: string | null;
    } | null;
    session: {
      id: string;
      userId: string;
      fresh: boolean;
      expiresAt: Date;
    } | null;
  };
};

/**
 * Validates the session cookie and populates c.var.user / c.var.session.
 * Does NOT reject unauthenticated requests — routes must check c.var.user themselves.
 */
export function sessionMiddleware(lucia: AppLucia) {
  return async (c: Context<AuthEnv>, next: Next) => {
    const sessionId = getCookie(c, lucia.sessionCookieName) ?? null;

    if (!sessionId) {
      c.set("user", null);
      c.set("session", null);
      return next();
    }

    const { session, user } = await lucia.validateSession(sessionId);

    if (session?.fresh) {
      const cookie = lucia.createSessionCookie(session.id);
      c.header("Set-Cookie", cookie.serialize(), { append: true });
    }

    if (!session) {
      const blankCookie = lucia.createBlankSessionCookie();
      c.header("Set-Cookie", blankCookie.serialize(), { append: true });
    }

    c.set(
      "user",
      user
        ? {
            id: user.id,
            email: user.email,
            displayName: user.displayName,
          }
        : null
    );
    c.set("session", session);

    return next();
  };
}

/**
 * Hard auth guard — returns 401 JSON if the user is not authenticated.
 */
export function requireAuth(lucia: AppLucia) {
  return async (c: Context<AuthEnv>, next: Next) => {
    const user = c.get("user");
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return next();
  };
}
