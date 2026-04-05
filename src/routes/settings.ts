import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
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

export function settingsRoutes(_db: unknown) {
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

  // GET /providers/hive-id-status — JSON Hive-ID health check (for live refresh)
  app.get("/providers/hive-id-status", async (c) => {
    if (!isOwner(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const status = await checkHiveId();
    return c.json(status);
  });

  // POST /providers/hive-id-url — inform operator to update HIVE_ID_URL env var
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

  return app;
}
