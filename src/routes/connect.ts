import { eq, and } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections } from "../db/schema.js";
import { decrypt } from "../crypto.js";

export function connectRoutes(db: DrizzleDb) {
  const app = new Hono<AuthEnv & { Variables: { identity?: NetworkIdentity } }>();

  app.get("/", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // In local mode without session, show all connections (owner has full access)
    const rows = user
      ? await db.select().from(connections).where(eq(connections.userId, user.id))
      : await db.select().from(connections);

    const result = rows.map((row) => ({
      id: row.id,
      provider: row.provider,
      role: row.role,
      accountLabel: row.accountLabel,
      scopes: row.scopes,
      tokenExpiresAt: row.tokenExpiresAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    }));

    return c.json(result);
  });

  app.delete("/:id", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const connectionId = c.req.param("id");

    // In local mode without session, owner can delete any connection
    const [existing] = user
      ? await db.select().from(connections).where(and(eq(connections.id, connectionId), eq(connections.userId, user.id))).limit(1)
      : await db.select().from(connections).where(eq(connections.id, connectionId)).limit(1);

    if (!existing) {
      return c.json({ error: "Connection not found" }, 404);
    }

    await db.delete(connections).where(eq(connections.id, connectionId));

    return c.json({ success: true });
  });

  return app;
}
