import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { providerSettings } from "../db/schema.js";
import { encrypt } from "../crypto.js";
import { readView } from "../views/loader.js";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Hive-ID health check
// ---------------------------------------------------------------------------

interface HiveIdStatus {
  reachable: boolean;
  providers: string[];
  url: string;
}

async function checkHiveId(): Promise<HiveIdStatus> {
  const config = getConfig();
  const url = config.hiveIdUrl;
  try {
    const res = await fetch(`${url}/.well-known/mycelium-node.json`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return { reachable: false, providers: [], url };
    }
    const manifest = await res.json() as { providers?: string[] };
    return { reachable: true, providers: manifest.providers ?? [], url };
  } catch {
    return { reachable: false, providers: [], url };
  }
}

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

  // GET /providers — settings page (HTML)
  app.get("/providers", async (c) => {
    if (!isOwner(c)) {
      return c.redirect("/auth/login?redirect=/settings/providers");
    }

    const config = getConfig();
    const hiveStatus = await checkHiveId();

    const html = await readView("settings-providers.html");
    const content = html
      .replace("{{hive_id_url}}", config.hiveIdUrl)
      .replace("{{hive_id_status_json}}", JSON.stringify(hiveStatus));

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

  // GET /providers/hive-id-status — JSON Hive-ID health check (for live refresh)
  app.get("/providers/hive-id-status", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const status = await checkHiveId();
    return c.json(status);
  });

  // POST /providers/hive-id-url — save a new Hive-ID URL
  // The URL is loaded from the HIVE_ID_URL env var at startup. This endpoint
  // informs the user to update their environment and restart the service.
  app.post("/providers/hive-id-url", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { url?: string };
    const newUrl = body.url?.trim();

    if (!newUrl || !newUrl.startsWith("http")) {
      return c.json({ error: "A valid HTTP/HTTPS URL is required" }, 400);
    }

    // Validate the URL parses cleanly
    try {
      new URL(newUrl);
    } catch {
      return c.json({ error: "Invalid URL format" }, 400);
    }

    // Log the requested change — the operator must update HIVE_ID_URL in their
    // environment and restart the service. This is intentional: env vars are the
    // authoritative source for service configuration.
    console.log(`[settings] Hive-ID URL change requested: ${newUrl} (update HIVE_ID_URL env var and restart)`);

    return c.json({
      ok: true,
      message: `Update HIVE_ID_URL=${newUrl} in your environment and restart the service.`,
    });
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
