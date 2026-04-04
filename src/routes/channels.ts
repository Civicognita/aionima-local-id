/**
 * Channel Setup Routes — wizard UI and configuration API for messaging channels.
 *
 * Serves the channel setup wizard page and three API endpoints:
 *   GET  /channels/         — wizard HTML page
 *   GET  /channels/status   — current channel config status (redacted)
 *   POST /channels/test     — validate channel credentials against provider APIs
 *   POST /channels/save     — write channel config to ~/.agi/aionima.json
 *
 * In local mode the ID service runs on the same machine as the AGI gateway,
 * so reading/writing ~/.agi/aionima.json directly is safe and correct.
 */

import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import { readView } from "../views/loader.js";
import { getAvailableProviderIds } from "../providers/registry.js";
import type { DrizzleDb } from "../db/client.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ChannelsEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

interface ChannelEntry {
  id: string;
  enabled: boolean;
  config: Record<string, string>;
  ownerChannelId?: string;
}

interface AgiConfig {
  channels?: ChannelEntry[];
  [key: string]: unknown;
}

interface TestRequest {
  channelId: string;
  config: Record<string, unknown>;
}

interface SaveRequest {
  channelId: string;
  config: Record<string, unknown>;
  ownerChannelId: string;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const AGI_CONFIG_PATH = join(homedir(), ".agi", "aionima.json");

async function readAgiConfig(): Promise<AgiConfig> {
  try {
    const raw = await readFile(AGI_CONFIG_PATH, "utf8");
    return JSON.parse(raw) as AgiConfig;
  } catch {
    return {};
  }
}

async function writeAgiConfig(config: AgiConfig): Promise<void> {
  await writeFile(AGI_CONFIG_PATH, JSON.stringify(config, null, 2), "utf8");
}

/** Redact secrets from a channel entry before returning to the browser. */
function redactChannel(entry: ChannelEntry): Record<string, unknown> {
  const secretFields = new Set([
    "token", "accessToken", "refreshToken", "appSecret",
    "clientSecret", "verifyToken", "apiKey", "password",
  ]);
  const redacted: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(entry.config)) {
    redacted[k] = secretFields.has(k) ? (v ? "***" : "") : v;
  }
  return redacted;
}

// ---------------------------------------------------------------------------
// Credential test implementations
// ---------------------------------------------------------------------------

interface TestResult {
  ok: boolean;
  error?: string;
  details?: string;
}

async function testTelegram(config: Record<string, unknown>): Promise<TestResult> {
  const token = String(config["token"] ?? "");
  if (!token) return { ok: false, error: "Bot token is required." };

  try {
    const res = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/getMe`);
    const data = await res.json() as { ok: boolean; result?: { username?: string; first_name?: string }; description?: string };
    if (!data.ok) {
      return { ok: false, error: data.description ?? "Telegram API rejected the token." };
    }
    const name = data.result?.first_name ?? data.result?.username ?? "Unknown";
    return { ok: true, details: `@${data.result?.username ?? name} (${name})` };
  } catch (err) {
    return { ok: false, error: "Could not reach Telegram API." };
  }
}

async function testDiscord(config: Record<string, unknown>): Promise<TestResult> {
  const token = String(config["token"] ?? "");
  if (!token) return { ok: false, error: "Bot token is required." };

  try {
    const res = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bot ${token}` },
    });
    if (!res.ok) {
      const text = await res.text();
      return { ok: false, error: `Discord API error ${res.status}: ${text.slice(0, 120)}` };
    }
    const data = await res.json() as { username?: string; discriminator?: string };
    const tag = data.discriminator && data.discriminator !== "0"
      ? `${data.username}#${data.discriminator}`
      : (data.username ?? "unknown");
    return { ok: true, details: `Bot: ${tag}` };
  } catch {
    return { ok: false, error: "Could not reach Discord API." };
  }
}

async function testGmail(config: Record<string, unknown>): Promise<TestResult> {
  // Gmail uses OAuth — verify the connection exists in the ID service DB.
  // The wizard skips a live API call here; OAuth state is checked via /api/channels/status.
  const ownerEmail = String(config["ownerEmail"] ?? "");
  if (!ownerEmail) return { ok: false, error: "Owner email address is required." };
  return { ok: true, details: `Will use Google OAuth connection for ${ownerEmail}` };
}

async function testSignal(config: Record<string, unknown>): Promise<TestResult> {
  const apiUrl = String(config["apiUrl"] ?? "").replace(/\/$/, "");
  const phoneNumber = String(config["phoneNumber"] ?? "");
  if (!apiUrl) return { ok: false, error: "API URL is required." };
  if (!phoneNumber) return { ok: false, error: "Phone number is required." };

  try {
    const res = await fetch(`${apiUrl}/v1/about`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) {
      return { ok: false, error: `signal-cli API responded with HTTP ${res.status}.` };
    }
    const data = await res.json() as { versions?: string[] };
    const version = data.versions?.[0] ?? "unknown";
    return { ok: true, details: `signal-cli version ${version}` };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return { ok: false, error: `Could not reach signal-cli API: ${msg}` };
  }
}

async function testWhatsApp(config: Record<string, unknown>): Promise<TestResult> {
  const token = String(config["accessToken"] ?? "");
  const phoneNumberId = String(config["phoneNumberId"] ?? "");
  if (!token) return { ok: false, error: "Access token is required." };
  if (!phoneNumberId) return { ok: false, error: "Phone Number ID is required." };

  try {
    const url = `https://graph.facebook.com/v18.0/${encodeURIComponent(phoneNumberId)}?fields=display_phone_number,verified_name`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      const data = await res.json() as { error?: { message?: string } };
      return { ok: false, error: data.error?.message ?? `Meta API error ${res.status}.` };
    }
    const data = await res.json() as { display_phone_number?: string; verified_name?: string };
    return {
      ok: true,
      details: `${data.verified_name ?? "Business"} (${data.display_phone_number ?? phoneNumberId})`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return { ok: false, error: `Could not reach Meta Graph API: ${msg}` };
  }
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function channelRoutes(db?: DrizzleDb) {
  const app = new Hono<ChannelsEnv>();

  // -------------------------------------------------------------------------
  // GET / — wizard HTML page
  // -------------------------------------------------------------------------

  app.get("/", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.redirect("/auth/login?redirect=/channels");
    }

    // Read current status to inject initial data into the page
    const agiConfig = await readAgiConfig();
    const channelEntries: ChannelEntry[] = agiConfig.channels ?? [];

    // Also check OAuth connections for google (gmail)
    const statusMap: Record<string, { id: string; connected: boolean; accountLabel?: string }> = {};
    for (const entry of channelEntries) {
      statusMap[entry.id] = { id: entry.id, connected: entry.enabled };
    }

    // Get available OAuth providers (DB-configured + .env-configured)
    const availableProviders = db
      ? await getAvailableProviderIds(db)
      : [];

    const channelsHtml = await readView("channels.html");
    const content = channelsHtml
      .replace("{{channel_status_json}}", JSON.stringify(statusMap))
      .replace("{{available_providers_json}}", JSON.stringify(availableProviders));

    const layout = await readView("layout.html");
    const html = layout
      .replace("{{title}}", "Aionima ID — Channel Setup")
      .replace("{{content}}", content);

    return c.html(html);
  });

  // -------------------------------------------------------------------------
  // GET /status — return current channel config (secrets redacted)
  // -------------------------------------------------------------------------

  app.get("/status", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const agiConfig = await readAgiConfig();
    const channelEntries: ChannelEntry[] = agiConfig.channels ?? [];

    const channels = channelEntries.map((entry) => ({
      id: entry.id,
      connected: entry.enabled,
      config: redactChannel(entry),
    }));

    return c.json({ channels });
  });

  // -------------------------------------------------------------------------
  // POST /test — validate channel credentials
  // -------------------------------------------------------------------------

  app.post("/test", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json<TestRequest>().catch(() => null);
    if (!body || !body.channelId) {
      return c.json({ ok: false, error: "channelId is required." }, 400);
    }

    const { channelId, config } = body;

    let result: TestResult;

    switch (channelId) {
      case "telegram":
        result = await testTelegram(config);
        break;
      case "discord":
        result = await testDiscord(config);
        break;
      case "gmail":
        result = await testGmail(config);
        break;
      case "signal":
        result = await testSignal(config);
        break;
      case "whatsapp":
        result = await testWhatsApp(config);
        break;
      default:
        result = { ok: false, error: `Unknown channel: ${channelId}` };
    }

    return c.json(result);
  });

  // -------------------------------------------------------------------------
  // POST /save — persist channel config to ~/.agi/aionima.json
  // -------------------------------------------------------------------------

  app.post("/save", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json<SaveRequest>().catch(() => null);
    if (!body || !body.channelId) {
      return c.json({ ok: false, error: "channelId is required." }, 400);
    }

    const { channelId, config, ownerChannelId, enabled } = body;

    const validChannels = new Set(["telegram", "discord", "gmail", "signal", "whatsapp"]);
    if (!validChannels.has(channelId)) {
      return c.json({ ok: false, error: "Unknown channelId." }, 400);
    }

    try {
      const agiConfig = await readAgiConfig();
      const channels: ChannelEntry[] = agiConfig.channels ?? [];

      const existingIdx = channels.findIndex((ch) => ch.id === channelId);
      const entry: ChannelEntry = {
        id: channelId,
        enabled: enabled ?? true,
        config: Object.fromEntries(
          Object.entries(config).map(([k, v]) => [k, String(v ?? "")]),
        ),
        ownerChannelId: ownerChannelId ?? "",
      };

      if (existingIdx >= 0) {
        channels[existingIdx] = entry;
      } else {
        channels.push(entry);
      }

      agiConfig.channels = channels;
      await writeAgiConfig(agiConfig);

      return c.json({ ok: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      return c.json({ ok: false, error: `Failed to save config: ${msg}` }, 500);
    }
  });

  return app;
}
