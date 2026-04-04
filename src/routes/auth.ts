import { hash, verify } from "@node-rs/argon2";
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { nanoid } from "nanoid";
import type { AppLucia } from "../auth/lucia.js";
import type { AuthEnv } from "../auth/middleware.js";
import type { DrizzleDb } from "../db/client.js";
import { users } from "../db/schema.js";
import { eq } from "drizzle-orm";
import type { EntityService } from "../services/entity-service.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;

export function authRoutes(db: DrizzleDb, lucia: AppLucia, entityService: EntityService) {
  const app = new Hono<AuthEnv>();

  app.post("/register", async (c) => {
    let body: { email?: string; username?: string; password?: string; displayName?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    const { email, username, password, displayName } = body;

    // Must provide email or username (or both)
    if (!email && !username) {
      return c.json({ error: "An email or username is required" }, 400);
    }

    if (email && (typeof email !== "string" || !EMAIL_RE.test(email))) {
      return c.json({ error: "A valid email address is required" }, 400);
    }
    if (username && (typeof username !== "string" || !USERNAME_RE.test(username))) {
      return c.json({ error: "Username must be 3-32 characters (letters, numbers, _ -)" }, 400);
    }
    if (!password || typeof password !== "string" || password.length < 8) {
      return c.json({ error: "Password must be at least 8 characters" }, 400);
    }
    if (password.length > 256) {
      return c.json({ error: "Password too long" }, 400);
    }

    // Check for existing email/username
    if (email) {
      const existing = await db
        .select()
        .from(users)
        .where(eq(users.email, email.toLowerCase()))
        .limit(1);
      if (existing.length > 0) {
        return c.json({ error: "Email already registered" }, 409);
      }
    }
    if (username) {
      const existing = await db
        .select()
        .from(users)
        .where(eq(users.username, username.toLowerCase()))
        .limit(1);
      if (existing.length > 0) {
        return c.json({ error: "Username already taken" }, 409);
      }
    }

    const passwordHash = await hash(password);
    const userId = nanoid();

    // Determine if this is the genesis owner (first user on the node)
    const isGenesis = !(await entityService.hasGenesisOwner());

    await db.insert(users).values({
      id: userId,
      email: email ? email.toLowerCase() : null,
      username: username ? username.toLowerCase() : null,
      passwordHash,
      displayName: displayName?.trim() || username || email?.split("@")[0] || null,
      dashboardRole: isGenesis ? "admin" : "viewer",
    });

    // Auto-create entity for this user
    let entityInfo: { id: string; coaAlias: string; geid: string } | undefined;

    try {

      if (isGenesis) {
        // First user on this node becomes #E0 (genesis owner) with $A0 auto-bound
        const result = await entityService.createOwnerEntity(
          displayName?.trim() || username || email?.split("@")[0] || "Owner",
        );
        await entityService.linkUserToEntity(userId, result.owner.id);
        entityInfo = {
          id: result.owner.id,
          coaAlias: result.owner.coaAlias,
          geid: result.ownerGeid.geid,
        };
      } else {
        // Subsequent users get ~E{n} under #E0
        const genesisOwner = await entityService.getByAlias("#E0");
        if (genesisOwner) {
          const result = await entityService.createLocalUser(
            displayName?.trim() || username || email?.split("@")[0] || "User",
            genesisOwner.id,
            userId,
          );
          await entityService.linkUserToEntity(userId, result.entity.id);
          entityInfo = {
            id: result.entity.id,
            coaAlias: result.entity.coaAlias,
            geid: result.geid.geid,
          };
        }
      }
    } catch (e) {
      // Entity creation failed — user is still created, entity can be linked later
      console.error("Auto-entity creation failed:", e);
    }

    const session = await lucia.createSession(userId, {});
    const cookie = lucia.createSessionCookie(session.id);
    c.header("Set-Cookie", cookie.serialize(), { append: true });

    return c.json({ success: true, userId, entity: entityInfo });
  });

  app.post("/login", async (c) => {
    let body: { email?: string; username?: string; password?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    const { email, username, password } = body;

    if (!email && !username) {
      return c.json({ error: "Email or username is required" }, 400);
    }
    if (!password || typeof password !== "string") {
      return c.json({ error: "Password is required" }, 400);
    }
    if (password.length > 256) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    let user;
    if (email) {
      [user] = await db
        .select()
        .from(users)
        .where(eq(users.email, email.toLowerCase()))
        .limit(1);
    } else if (username) {
      [user] = await db
        .select()
        .from(users)
        .where(eq(users.username, username.toLowerCase()))
        .limit(1);
    }

    if (!user) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    const valid = await verify(user.passwordHash, password);
    if (!valid) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    const session = await lucia.createSession(user.id, {});
    const cookie = lucia.createSessionCookie(session.id);
    c.header("Set-Cookie", cookie.serialize(), { append: true });

    return c.json({ success: true, userId: user.id, entityId: user.entityId });
  });

  app.post("/logout", async (c) => {
    const sessionId = getCookie(c, lucia.sessionCookieName);

    if (sessionId) {
      await lucia.invalidateSession(sessionId);
    }

    const blankCookie = lucia.createBlankSessionCookie();
    c.header("Set-Cookie", blankCookie.serialize(), { append: true });

    return c.json({ success: true });
  });

  return app;
}
