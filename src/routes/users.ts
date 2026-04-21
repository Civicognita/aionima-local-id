/**
 * User Management Routes — CRUD endpoints for dashboard users.
 *
 * Each user is created with a linked entity + GEID in a single operation.
 * These endpoints are the single authority for user lifecycle in Phase 3.
 */

import { hash } from "@node-rs/argon2";
import { Hono } from "hono";
import { eq } from "drizzle-orm";
import type { DrizzleDb } from "../db/client.js";
import { users, entities, geidLocal } from "../db/schema.js";
import type { EntityService } from "../services/entity-service.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { AuthEnv } from "../auth/middleware.js";

const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;

type UserEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

export function userRoutes(db: DrizzleDb, entityService: EntityService) {
  const app = new Hono<UserEnv>();

  /**
   * Guard: require owner auth (private network or API key).
   */
  function requireOwner(c: any): Response | null {
    const identity = c.get("identity") as NetworkIdentity | undefined;
    if (!identity?.isOwner) {
      return c.json({ error: "Owner authentication required" }, 403);
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // GET /api/users — list all users with entity info + dashboardRole
  // -------------------------------------------------------------------------

  app.get("/", async (c) => {
    const denied = requireOwner(c);
    if (denied) return denied;

    const allUsers = await db.select().from(users);

    const result = await Promise.all(
      allUsers.map(async (user) => {
        let entity = null;
        let geid = null;

        if (user.entityId) {
          const [e] = await db.select().from(entities).where(eq(entities.id, user.entityId)).limit(1);
          entity = e ?? null;
          if (entity) {
            const [g] = await db.select().from(geidLocal).where(eq(geidLocal.entityId, entity.id)).limit(1);
            geid = g ?? null;
          }
        }

        return {
          id: user.id,
          username: user.username,
          email: user.email,
          displayName: user.displayName,
          dashboardRole: user.dashboardRole,
          createdAt: user.createdAt?.toISOString() ?? null,
          entity: entity
            ? {
                id: entity.id,
                coaAlias: entity.coaAlias,
                geid: geid?.geid ?? null,
              }
            : null,
        };
      }),
    );

    return c.json({ users: result });
  });

  // -------------------------------------------------------------------------
  // POST /api/users/create — create user + entity + GEID in one operation
  // -------------------------------------------------------------------------

  app.post("/create", async (c) => {
    const denied = requireOwner(c);
    if (denied) return denied;

    const body = await c.req.json().catch(() => ({})) as {
      username?: string;
      password?: string;
      displayName?: string;
      dashboardRole?: string;
    };

    const { username, password, displayName, dashboardRole } = body;

    if (!username || typeof username !== "string" || !USERNAME_RE.test(username)) {
      return c.json({ error: "Username must be 3-32 characters (letters, numbers, _ -)" }, 400);
    }
    if (!password || typeof password !== "string" || password.length < 8) {
      return c.json({ error: "Password must be at least 8 characters" }, 400);
    }
    if (password.length > 256) {
      return c.json({ error: "Password too long" }, 400);
    }

    const role = (dashboardRole ?? "viewer") as "admin" | "editor" | "viewer";
    if (!["admin", "editor", "viewer"].includes(role)) {
      return c.json({ error: "dashboardRole must be admin, editor, or viewer" }, 400);
    }

    // Check uniqueness
    const [existing] = await db
      .select()
      .from(users)
      .where(eq(users.username, username.toLowerCase()))
      .limit(1);
    if (existing) {
      return c.json({ error: "Username already taken" }, 409);
    }

    const passwordHash = await hash(password);
    const { nanoid } = await import("nanoid");
    const userId = nanoid();

    const name = displayName?.trim() || username;

    // Create user record. Virtual backend + username-as-principal keeps
    // `(auth_backend, principal)` unique alongside any future PAM/LDAP users.
    await db.insert(users).values({
      id: userId,
      authBackend: "virtual",
      principal: username.toLowerCase(),
      username: username.toLowerCase(),
      passwordHash,
      displayName: name,
      dashboardRole: role,
    });

    // Create entity under genesis owner (#E0)
    let entityInfo: { id: string; coaAlias: string; geid: string } | null = null;
    try {
      const genesisOwner = await entityService.getByAlias("#E0");
      if (genesisOwner) {
        const result = await entityService.createLocalUser(name, genesisOwner.id, userId);
        await entityService.linkUserToEntity(userId, result.entity.id);
        entityInfo = {
          id: result.entity.id,
          coaAlias: result.entity.coaAlias,
          geid: result.geid.geid,
        };
      }
    } catch (e) {
      console.error("Entity creation for new user failed:", e);
    }

    return c.json({
      user: {
        id: userId,
        username: username.toLowerCase(),
        displayName: name,
        dashboardRole: role,
      },
      entity: entityInfo,
    }, 201);
  });

  // -------------------------------------------------------------------------
  // PUT /api/users/:id — update displayName, dashboardRole
  // -------------------------------------------------------------------------

  app.put("/:id", async (c) => {
    const denied = requireOwner(c);
    if (denied) return denied;

    const userId = c.req.param("id");
    const body = await c.req.json().catch(() => ({})) as {
      displayName?: string;
      dashboardRole?: string;
    };

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    const updates: Partial<{ displayName: string; dashboardRole: "admin" | "editor" | "viewer" }> = {};

    if (body.displayName !== undefined) {
      updates.displayName = body.displayName.trim();
    }
    if (body.dashboardRole !== undefined) {
      if (!["admin", "editor", "viewer"].includes(body.dashboardRole)) {
        return c.json({ error: "dashboardRole must be admin, editor, or viewer" }, 400);
      }
      updates.dashboardRole = body.dashboardRole as "admin" | "editor" | "viewer";
    }

    if (Object.keys(updates).length === 0) {
      return c.json({ error: "No fields to update" }, 400);
    }

    await db.update(users).set(updates).where(eq(users.id, userId));

    // If displayName changed, also update the linked entity
    if (updates.displayName && user.entityId) {
      await db
        .update(entities)
        .set({ displayName: updates.displayName, updatedAt: new Date() })
        .where(eq(entities.id, user.entityId));
    }

    const [updated] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    return c.json({
      ok: true,
      user: {
        id: updated!.id,
        username: updated!.username,
        displayName: updated!.displayName,
        dashboardRole: updated!.dashboardRole,
      },
    });
  });

  // -------------------------------------------------------------------------
  // PUT /api/users/:id/password — reset password
  // -------------------------------------------------------------------------

  app.put("/:id/password", async (c) => {
    const denied = requireOwner(c);
    if (denied) return denied;

    const userId = c.req.param("id");
    const body = await c.req.json().catch(() => ({})) as { password?: string };

    if (!body.password || typeof body.password !== "string" || body.password.length < 8) {
      return c.json({ error: "Password must be at least 8 characters" }, 400);
    }
    if (body.password.length > 256) {
      return c.json({ error: "Password too long" }, 400);
    }

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    const passwordHash = await hash(body.password);
    await db.update(users).set({ passwordHash }).where(eq(users.id, userId));

    return c.json({ ok: true });
  });

  // -------------------------------------------------------------------------
  // DELETE /api/users/:id — soft-delete (disable entity)
  // -------------------------------------------------------------------------

  app.delete("/:id", async (c) => {
    const denied = requireOwner(c);
    if (denied) return denied;

    const userId = c.req.param("id");

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Prevent deleting the genesis owner
    if (user.entityId) {
      const [entity] = await db.select().from(entities).where(eq(entities.id, user.entityId)).limit(1);
      if (entity?.coaAlias === "#E0") {
        return c.json({ error: "Cannot delete the genesis owner" }, 403);
      }
    }

    // Soft-delete: set verification tier to "disabled" on the entity
    if (user.entityId) {
      await db
        .update(entities)
        .set({ verificationTier: "disabled", updatedAt: new Date() })
        .where(eq(entities.id, user.entityId));
    }

    // Delete the user record
    await db.delete(users).where(eq(users.id, userId));

    return c.json({ ok: true });
  });

  return app;
}
