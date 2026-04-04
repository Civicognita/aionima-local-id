/**
 * OAuth Delegation Routes — proxies OAuth flows through Hive-ID.
 *
 * Local-ID cannot receive OAuth callbacks from external providers (Google,
 * GitHub, Discord) because `id.ai.on` is not reachable from the public
 * internet. Instead, these flows are delegated to Hive-ID (`id.aionima.ai`),
 * which has a public URL and registered OAuth callback URIs.
 *
 * Flow:
 *   1. Browser calls POST /api/oauth/delegate  → Local-ID asks Hive-ID to
 *      create a handoff, stores the handoffId, returns a popup URL.
 *   2. Browser opens the popup URL (points to Hive-ID's handoff page).
 *   3. User completes OAuth at Hive-ID.
 *   4. Browser polls GET /api/oauth/delegate/poll → Local-ID polls Hive-ID
 *      for the handoff result. On completion, tokens are stored locally.
 *
 * Token channels (Telegram, Discord bot tokens, Signal, WhatsApp) are NOT
 * handled here — they are entered directly in the channel wizard.
 */

import { randomBytes } from "node:crypto";
import { eq, and } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, users } from "../db/schema.js";
import { encrypt } from "../crypto.js";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type DelegateEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

interface HiveHandoffCreateResponse {
  handoffId: string;
  authUrl: string;
}

interface HiveConnectionSnapshot {
  provider: string;
  role: string;
  accountLabel: string | null;
  accessToken: string | null;
  refreshToken: string | null;
}

interface HiveHandoffPollResponse {
  status: "pending" | "completed" | "expired" | "not_found";
  services?: HiveConnectionSnapshot[];
}

interface PendingDelegation {
  handoffId: string;
  provider: string;
  role: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// In-memory pending delegation store
// One delegation at a time per process — Local-ID is single-tenant.
// TTL: 20 minutes (matches Hive-ID's handoff TTL with buffer).
// ---------------------------------------------------------------------------

const DELEGATION_TTL_MS = 20 * 60 * 1000;
let pendingDelegation: PendingDelegation | null = null;

function clearStaleDelegation(): void {
  if (pendingDelegation && Date.now() - pendingDelegation.createdAt > DELEGATION_TTL_MS) {
    pendingDelegation = null;
  }
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function oauthDelegateRoutes(db: DrizzleDb) {
  const app = new Hono<DelegateEnv>();

  /**
   * POST /api/oauth/delegate
   *
   * Starts an OAuth delegation flow via Hive-ID.
   * Body: { provider: string, role: string }
   * Returns: { popupUrl: string }
   */
  app.post("/", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { provider?: string; role?: string };
    const provider = body.provider;
    const role = body.role ?? "owner";

    const validProviders = new Set(["google", "github", "discord"]);
    if (!provider || !validProviders.has(provider)) {
      return c.json({ error: "Invalid provider. Must be one of: google, github, discord" }, 400);
    }

    const config = getConfig();

    // Ask Hive-ID to create a handoff for this OAuth provider
    let hiveResponse: HiveHandoffCreateResponse;
    try {
      const res = await fetch(`${config.hiveIdUrl}/api/handoff/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ purpose: `oauth:${provider}:${role}` }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return c.json(
          { error: `Hive-ID returned HTTP ${res.status}: ${text.slice(0, 200)}` },
          502,
        );
      }

      hiveResponse = await res.json() as HiveHandoffCreateResponse;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      return c.json({ error: `Cannot reach Hive-ID: ${msg}` }, 502);
    }

    if (!hiveResponse.handoffId || !hiveResponse.authUrl) {
      return c.json({ error: "Hive-ID returned an invalid handoff response" }, 502);
    }

    // Store the pending delegation (replaces any previous one)
    clearStaleDelegation();
    pendingDelegation = {
      handoffId: hiveResponse.handoffId,
      provider,
      role,
      createdAt: Date.now(),
    };

    return c.json({ popupUrl: hiveResponse.authUrl });
  });

  /**
   * GET /api/oauth/delegate/poll
   *
   * Polls Hive-ID for the result of the pending delegation.
   * If complete, stores received tokens in local DB and clears the pending delegation.
   * Returns: { complete: boolean, provider?: string, accountLabel?: string, error?: string }
   */
  app.get("/poll", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    clearStaleDelegation();

    if (!pendingDelegation) {
      return c.json({ complete: false, error: "No pending delegation" });
    }

    const { handoffId, provider, role } = pendingDelegation;
    const config = getConfig();

    // Poll Hive-ID for the handoff result
    let pollResponse: HiveHandoffPollResponse;
    try {
      const res = await fetch(`${config.hiveIdUrl}/api/handoff/${handoffId}/poll`, {
        signal: AbortSignal.timeout(8_000),
      });

      if (!res.ok) {
        return c.json({ complete: false });
      }

      pollResponse = await res.json() as HiveHandoffPollResponse;
    } catch {
      return c.json({ complete: false });
    }

    if (pollResponse.status === "pending") {
      return c.json({ complete: false });
    }

    if (pollResponse.status === "expired" || pollResponse.status === "not_found") {
      pendingDelegation = null;
      return c.json({ complete: false, error: "Handoff expired or not found" });
    }

    if (pollResponse.status !== "completed") {
      return c.json({ complete: false });
    }

    // Handoff completed — store the matching token locally
    const services = pollResponse.services ?? [];
    const matchingService = services.find(
      (s) => s.provider === provider && s.role === role,
    );

    pendingDelegation = null;

    if (!matchingService) {
      // Completed but no matching service — provider may not have been connected
      return c.json({
        complete: true,
        provider,
        accountLabel: null,
        warning: "No token received for this provider",
      });
    }

    // Find or create a synthetic user ID for local storage.
    // Local-ID is single-tenant, so connections are stored against the
    // first user in the DB (or a sentinel ID if no users exist).
    const userId = await resolveLocalUserId(db);

    // Upsert the connection — replace any existing entry for this provider+role
    const now = new Date();
    const encAccessToken = matchingService.accessToken
      ? encrypt(matchingService.accessToken)
      : null;
    const encRefreshToken = matchingService.refreshToken
      ? encrypt(matchingService.refreshToken)
      : null;

    const [existing] = await db
      .select()
      .from(connections)
      .where(and(eq(connections.userId, userId), eq(connections.provider, provider), eq(connections.role, role)))
      .limit(1);

    if (existing) {
      await db
        .update(connections)
        .set({
          accountLabel: matchingService.accountLabel,
          accessToken: encAccessToken,
          refreshToken: encRefreshToken,
          updatedAt: now,
        })
        .where(eq(connections.id, existing.id));
    } else {
      await db.insert(connections).values({
        id: randomBytes(16).toString("hex"),
        userId,
        provider,
        role,
        accountLabel: matchingService.accountLabel,
        accessToken: encAccessToken,
        refreshToken: encRefreshToken,
        createdAt: now,
        updatedAt: now,
      });
    }

    return c.json({
      complete: true,
      provider,
      accountLabel: matchingService.accountLabel,
    });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a local user ID to attach incoming connections to.
 *
 * Local-ID is single-tenant. Connections from OAuth delegation come from the
 * owner and should be stored against the first (owner) user. If no users
 * exist yet, use a well-known sentinel ID — the connection will still be
 * visible to the owner (private-network auth shows all connections).
 */
async function resolveLocalUserId(db: DrizzleDb): Promise<string> {
  const [firstUser] = await db.select({ id: users.id }).from(users).limit(1);
  return firstUser?.id ?? "local-owner";
}
