import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { providerSettings } from "../db/schema.js";
import { encrypt, decrypt } from "../crypto.js";
import { readView } from "../views/loader.js";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SettingsEnv = AuthEnv & { Variables: { identity?: NetworkIdentity } };

// ---------------------------------------------------------------------------
// Owner guard helper
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isOwner(c: any): boolean {
  const user = c.get("user");
  const identity = c.get("identity") as NetworkIdentity | undefined;
  return !!user || identity?.isOwner === true;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

const KNOWN_PROVIDERS = ["google", "github", "discord"] as const;

export function settingsRoutes(db: DrizzleDb) {
  const app = new Hono<SettingsEnv>();

  // GET /providers — settings wizard page (HTML)
  app.get("/providers", async (c) => {
    if (!isOwner(c)) {
      return c.redirect("/auth/login?redirect=/settings/providers");
    }

    const rows = await db.select().from(providerSettings);
    const providers = KNOWN_PROVIDERS.map((id) => {
      const row = rows.find((r) => r.id === id);
      return {
        id,
        configured: !!row?.clientId,
        enabled: row?.enabled ?? false,
        clientIdPreview: row?.clientId
          ? decrypt(row.clientId).slice(0, 8) + "..."
          : null,
        configuredAt: row?.configuredAt?.toISOString() ?? null,
      };
    });

    const config = getConfig();
    const baseUrl = config.baseUrl;

    const html = await readView("settings-providers.html");
    const content = html
      .replace("{{providers_json}}", JSON.stringify(providers))
      .replace(/\{\{base_url\}\}/g, baseUrl);

    const layout = await readView("layout.html");
    return c.html(
      layout
        .replace("{{title}}", "Aionima ID — Provider Settings")
        .replace("{{content}}", content),
    );
  });

  // GET /providers/status — JSON status of all providers
  app.get("/providers/status", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const rows = await db.select().from(providerSettings);
    return c.json(
      rows.map((r) => ({
        id: r.id,
        configured: !!r.clientId,
        enabled: r.enabled,
        configuredAt: r.configuredAt?.toISOString() ?? null,
      })),
    );
  });

  // POST /providers/:id — save (upsert) credentials for a provider
  app.post("/providers/:id", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const providerId = c.req.param("id");
    if (!(KNOWN_PROVIDERS as readonly string[]).includes(providerId)) {
      return c.json({ error: "Invalid provider" }, 400);
    }

    const body = (await c.req.json()) as {
      clientId?: string;
      clientSecret?: string;
    };

    if (!body.clientId || !body.clientSecret) {
      return c.json({ error: "clientId and clientSecret are required" }, 400);
    }

    const encClientId = encrypt(body.clientId);
    const encClientSecret = encrypt(body.clientSecret);
    const now = new Date();

    const existing = await db
      .select()
      .from(providerSettings)
      .where(eq(providerSettings.id, providerId))
      .limit(1);

    if (existing.length > 0) {
      await db
        .update(providerSettings)
        .set({
          clientId: encClientId,
          clientSecret: encClientSecret,
          enabled: true,
          updatedAt: now,
        })
        .where(eq(providerSettings.id, providerId));
    } else {
      await db.insert(providerSettings).values({
        id: providerId,
        clientId: encClientId,
        clientSecret: encClientSecret,
        enabled: true,
        configuredAt: now,
        updatedAt: now,
      });
    }

    return c.json({ ok: true });
  });

  // DELETE /providers/:id — remove credentials for a provider
  app.delete("/providers/:id", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const providerId = c.req.param("id");
    if (!(KNOWN_PROVIDERS as readonly string[]).includes(providerId)) {
      return c.json({ error: "Invalid provider" }, 400);
    }

    await db
      .delete(providerSettings)
      .where(eq(providerSettings.id, providerId));

    return c.json({ ok: true });
  });

  return app;
}
