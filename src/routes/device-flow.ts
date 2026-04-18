/**
 * Device Flow Routes — implements RFC 8628 OAuth 2.0 Device Authorization Grant.
 *
 * Unlike the standard OAuth delegation flow (which requires a public callback
 * URL via Hive-ID), Device Flow is fully self-contained: the provider sends
 * the user to a verification URL and Local-ID polls for the token. This works
 * on any network without any public-facing redirect URI.
 *
 * Supported providers: GitHub, Google, Discord
 *
 * Flow:
 *   1. POST /api/auth/device-flow/start  → initiates with provider, returns
 *      user_code + verification_uri for the user to visit in a browser.
 *   2. GET  /api/auth/device-flow/poll?deviceCode=...  → polls the provider
 *      token endpoint. Returns pending/expired/completed status.
 *      On completion, stores encrypted tokens in the connections table.
 *   3. GET  /api/auth/device-flow/status → lists stored connections.
 *   4. POST /api/auth/device-flow/refresh → refreshes a Google access token
 *      using its stored refresh token.
 */

import { randomBytes } from "node:crypto";
import { eq, and } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, users } from "../db/schema.js";
import { encrypt, decrypt } from "../crypto.js";
// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type DeviceFlowEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

type ProviderName = "github" | "google" | "discord";

interface DeviceSession {
  provider: ProviderName;
  role: string;
  deviceCode: string;
  expiresAt: number;
  /** Current polling interval in seconds (may grow on slow_down responses) */
  interval: number;
}

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

const PROVIDERS: Record<ProviderName, {
  deviceCodeUrl: string;
  tokenUrl: string;
  scopes: string;
  grantType: string;
}> = {
  github: {
    deviceCodeUrl: "https://github.com/login/device/code",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scopes: "repo read:user user:email",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
  google: {
    deviceCodeUrl: "https://oauth2.googleapis.com/device/code",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: "https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
  discord: {
    deviceCodeUrl: "https://discord.com/api/v10/oauth2/device/authorize",
    tokenUrl: "https://discord.com/api/v10/oauth2/token",
    scopes: "identify guilds",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
};

// ---------------------------------------------------------------------------
// In-memory session store for active device flow sessions.
// Keyed by device_code returned by the provider.
// Local-ID is single-tenant — a Map is sufficient.
// TTL is enforced by expiresAt on each session entry.
// ---------------------------------------------------------------------------

const activeSessions = new Map<string, DeviceSession>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Civicognita-registered OAuth App client IDs — public, shipped with the application.
// Device Flow (RFC 8628) uses public clients — no client_secret needed for GitHub.
// Google and Discord require client_secret for token exchange even in device flow,
// so those are included here. These are APPLICATION secrets (not user secrets) and
// are safe to ship — they cannot be used without user consent via the device flow.
const OAUTH_CLIENTS: Record<ProviderName, { clientId: string; clientSecret?: string }> = {
  github: {
    clientId: "PLACEHOLDER_GITHUB_CLIENT_ID",
  },
  google: {
    clientId: "PLACEHOLDER_GOOGLE_CLIENT_ID",
    clientSecret: "PLACEHOLDER_GOOGLE_CLIENT_SECRET",
  },
  discord: {
    clientId: "PLACEHOLDER_DISCORD_CLIENT_ID",
    clientSecret: "PLACEHOLDER_DISCORD_CLIENT_SECRET",
  },
};

/**
 * Resolve the local user ID to attach connections to.
 * Local-ID is single-tenant — use the first user or the well-known sentinel.
 */
async function resolveLocalUserId(db: DrizzleDb): Promise<string> {
  const [firstUser] = await db.select({ id: users.id }).from(users).limit(1);
  return firstUser?.id ?? "local-owner";
}

/**
 * Fetch the account label (username/email) from the provider's user info endpoint.
 * Non-fatal — returns empty string on failure.
 */
async function fetchAccountLabel(
  provider: ProviderName,
  accessToken: string,
  tokenType: string,
): Promise<string> {
  try {
    if (provider === "github") {
      const res = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `${tokenType} ${accessToken}`,
          "User-Agent": "Aionima-Local-ID",
        },
      });
      const user = await res.json() as { login?: string };
      return user.login ?? "";
    }

    if (provider === "google") {
      const res = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user = await res.json() as { email?: string };
      return user.email ?? "";
    }

    if (provider === "discord") {
      const res = await fetch("https://discord.com/api/v10/users/@me", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user = await res.json() as { global_name?: string; username?: string };
      return user.global_name ?? user.username ?? "";
    }
  } catch {
    // Non-fatal — account label is display-only
  }
  return "";
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function deviceFlowRoutes(db: DrizzleDb) {
  const app = new Hono<DeviceFlowEnv>();

  /**
   * POST /start
   *
   * Initiates a device authorization flow with the given provider.
   * Body: { provider: "github" | "google" | "discord", role?: string }
   * Returns: { deviceCode, userCode, verificationUri, expiresIn, interval }
   */
  app.post("/start", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { provider?: string; role?: string };
    const provider = body.provider as ProviderName | undefined;
    const role = body.role ?? "owner";

    if (!provider || !(provider in PROVIDERS)) {
      return c.json(
        { error: `Invalid provider. Supported: ${Object.keys(PROVIDERS).join(", ")}` },
        400,
      );
    }

    const creds = OAUTH_CLIENTS[provider];
    if (!creds.clientId) {
      return c.json(
        { error: `${provider} OAuth client not configured. Set ${provider.toUpperCase()}_CLIENT_ID in environment.` },
        400,
      );
    }

    const providerCfg = PROVIDERS[provider];

    const params = new URLSearchParams();
    params.set("client_id", creds.clientId);
    params.set("scope", providerCfg.scopes);

    let data: {
      device_code: string;
      user_code: string;
      verification_uri?: string;
      verification_url?: string;
      expires_in: number;
      interval?: number;
    };

    try {
      const res = await fetch(providerCfg.deviceCodeUrl, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return c.json({ error: `Provider returned ${res.status}: ${text.slice(0, 200)}` }, 502);
      }

      data = await res.json() as typeof data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: `Failed to reach ${provider}: ${msg}` }, 502);
    }

    // Store session keyed by device_code
    activeSessions.set(data.device_code, {
      provider,
      role,
      deviceCode: data.device_code,
      expiresAt: Date.now() + data.expires_in * 1000,
      interval: data.interval ?? 5,
    });

    return c.json({
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri ?? data.verification_url ?? "",
      expiresIn: data.expires_in,
      interval: data.interval ?? 5,
    });
  });

  /**
   * GET /poll?deviceCode=...
   *
   * Polls the provider token endpoint to check if the user has authorized.
   * Returns: { status: "pending" | "expired" | "completed" | "error", ... }
   *
   * On "completed", tokens are encrypted and stored in the connections table.
   */
  app.get("/poll", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const deviceCode = c.req.query("deviceCode");
    if (!deviceCode) {
      return c.json({ error: "deviceCode query parameter is required" }, 400);
    }

    const session = activeSessions.get(deviceCode);
    if (!session) {
      return c.json({ status: "expired" });
    }
    if (Date.now() > session.expiresAt) {
      activeSessions.delete(deviceCode);
      return c.json({ status: "expired" });
    }

    const provider = session.provider;
    const providerCfg = PROVIDERS[provider];
    const creds = OAUTH_CLIENTS[provider];

    const params = new URLSearchParams();
    params.set("client_id", creds.clientId);
    if (creds.clientSecret) params.set("client_secret", creds.clientSecret);
    params.set("device_code", session.deviceCode);
    params.set("grant_type", providerCfg.grantType);

    let data: Record<string, unknown>;
    try {
      const res = await fetch(providerCfg.tokenUrl, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(10_000),
      });
      data = await res.json() as Record<string, unknown>;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ status: "error", error: `Token poll failed: ${msg}` });
    }

    const error = data.error as string | undefined;

    if (error === "authorization_pending") {
      return c.json({ status: "pending", interval: session.interval });
    }

    if (error === "slow_down") {
      session.interval = (session.interval ?? 5) + 5;
      return c.json({ status: "pending", interval: session.interval });
    }

    if (error === "expired_token" || error === "access_denied") {
      activeSessions.delete(deviceCode);
      return c.json({ status: "expired", error });
    }

    if (error) {
      return c.json({
        status: "error",
        error: String(data.error_description ?? error),
      });
    }

    // Authorization granted
    const accessToken = data.access_token as string;
    const refreshToken = data.refresh_token as string | undefined;
    const tokenType = (data.token_type as string | undefined) ?? "Bearer";
    const scope = data.scope as string | undefined;
    const expiresIn = data.expires_in as number | undefined;

    // Fetch display label — non-fatal
    const accountLabel = await fetchAccountLabel(provider, accessToken, tokenType);

    // Persist to connections table
    const userId = await resolveLocalUserId(db);
    const now = new Date();
    const encAccessToken = encrypt(accessToken);
    const encRefreshToken = refreshToken ? encrypt(refreshToken) : null;
    const tokenExpiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    const [existing] = await db
      .select()
      .from(connections)
      .where(and(
        eq(connections.userId, userId),
        eq(connections.provider, provider),
        eq(connections.role, session.role),
      ))
      .limit(1);

    if (existing) {
      await db
        .update(connections)
        .set({
          accountLabel,
          accessToken: encAccessToken,
          refreshToken: encRefreshToken,
          tokenExpiresAt,
          scopes: scope ?? null,
          updatedAt: now,
        })
        .where(eq(connections.id, existing.id));
    } else {
      await db.insert(connections).values({
        id: randomBytes(16).toString("hex"),
        userId,
        provider,
        role: session.role,
        accountLabel,
        accessToken: encAccessToken,
        refreshToken: encRefreshToken,
        tokenExpiresAt,
        scopes: scope ?? null,
        createdAt: now,
        updatedAt: now,
      });
    }

    activeSessions.delete(deviceCode);

    return c.json({
      status: "completed",
      provider,
      role: session.role,
      accountLabel,
    });
  });

  /**
   * GET /status
   *
   * Lists all stored OAuth connections (provider, role, accountLabel).
   * Does not expose tokens.
   */
  app.get("/status", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const rows = await db.select({
      provider: connections.provider,
      role: connections.role,
      accountLabel: connections.accountLabel,
      scopes: connections.scopes,
      tokenExpiresAt: connections.tokenExpiresAt,
      updatedAt: connections.updatedAt,
    }).from(connections);

    return c.json(rows);
  });

  /**
   * POST /refresh
   *
   * Refreshes a Google access token using its stored refresh token.
   * Body: { provider: "google", role?: string }
   * Returns: { ok: true, expiresIn: number }
   */
  app.post("/refresh", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { provider?: string; role?: string };
    const provider = body.provider as ProviderName | undefined;
    const role = body.role ?? "owner";

    if (provider !== "google") {
      return c.json({ error: "Token refresh is only supported for Google" }, 400);
    }

    const creds = OAUTH_CLIENTS[provider];

    const [conn] = await db
      .select()
      .from(connections)
      .where(and(
        eq(connections.provider, provider),
        eq(connections.role, role),
      ))
      .limit(1);

    if (!conn?.refreshToken) {
      return c.json({ error: "No refresh token found for this provider/role" }, 404);
    }

    const refreshToken = decrypt(conn.refreshToken);

    const params = new URLSearchParams();
    params.set("client_id", creds.clientId);
    if (creds.clientSecret) params.set("client_secret", creds.clientSecret);
    params.set("refresh_token", refreshToken);
    params.set("grant_type", "refresh_token");

    let data: { access_token?: string; expires_in?: number; error?: string };
    try {
      const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
        signal: AbortSignal.timeout(10_000),
      });
      data = await res.json() as typeof data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: `Refresh request failed: ${msg}` }, 502);
    }

    if (data.error || !data.access_token) {
      return c.json({ error: `Refresh failed: ${data.error ?? "no access_token in response"}` }, 502);
    }

    const encAccessToken = encrypt(data.access_token);
    const tokenExpiresAt = data.expires_in
      ? new Date(Date.now() + data.expires_in * 1000)
      : null;

    await db
      .update(connections)
      .set({ accessToken: encAccessToken, tokenExpiresAt, updatedAt: new Date() })
      .where(eq(connections.id, conn.id));

    return c.json({ ok: true, expiresIn: data.expires_in ?? null });
  });

  return app;
}
