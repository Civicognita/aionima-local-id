/**
 * Handoff Routes — secure token delivery from ID service to AGI gateways.
 *
 * Two modes of operation:
 *
 * **Central mode** (id.aionima.ai):
 *   1. Gateway creates a handoff (POST /create) — gets handoffId + authUrl
 *   2. User opens authUrl in popup — logs in via email/password, sees approve page
 *   3. User clicks approve — OAuth tokens are snapshot and encrypted
 *   4. Gateway polls (GET /:id/poll) — receives tokens once, handoff deleted
 *
 * **Local mode** (id.ai.on or similar):
 *   1. Gateway creates a handoff with node API key — handoff auto-identifies owner
 *   2. Private network requests to the handoff page auto-approve (no login needed)
 *   3. If OAuth tokens exist, they're included. If not, handoff still succeeds.
 *   4. The network IS the credential — being on the LAN proves you're the owner.
 *
 * The `purpose` field controls which providers are shown and included:
 * - "onboarding" — all providers (default)
 * - "channel:discord" — only Discord OAuth
 * - "channel:gmail" — only Google OAuth with Gmail scopes
 */

import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppLucia } from "../auth/lucia.js";
import type { AuthEnv } from "../auth/middleware.js";
import { decrypt, encrypt } from "../crypto.js";
import { escapeHtml } from "../security/escape.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, entities, geidLocal, handoffs, users } from "../db/schema.js";
import { readView } from "../views/loader.js";
import { getConfig } from "../config.js";
import type { NetworkIdentity } from "../auth/network-identity.js";

const TTL_MS = 15 * 60 * 1000; // 15 minutes

interface ConnectionSnapshot {
  provider: string;
  role: string;
  accountLabel: string | null;
  accessToken: string | null;
  refreshToken: string | null;
}

/** Map a purpose string to the provider IDs it allows. null = all providers. */
function purposeToProviderFilter(purpose: string | null): string[] | null {
  if (!purpose || purpose === "onboarding") return null;
  if (purpose.startsWith("channel:")) {
    const channel = purpose.slice("channel:".length);
    const channelProviderMap: Record<string, string[]> = {
      discord: ["discord"],
      gmail: ["google"],
      email: ["google"],
      github: ["github"],
    };
    return channelProviderMap[channel] ?? null;
  }
  return null;
}

// Augmented env type with network identity
type HandoffEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

export function handoffRoutes(db: DrizzleDb, lucia: AppLucia) {
  const app = new Hono<HandoffEnv>();

  /**
   * POST /api/handoff/create
   *
   * Central mode: no auth required, creates pending handoff.
   * Local mode: if called from private network or with node API key,
   * the handoff is pre-identified as the owner (no login step needed).
   */
  app.post("/create", async (c) => {
    const body = await c.req.json().catch(() => ({})) as { purpose?: string };
    const purpose = body.purpose ?? "onboarding";
    const config = getConfig();

    const handoffId = randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + TTL_MS);

    await db.insert(handoffs).values({
      id: handoffId,
      userId: null,
      status: "pending",
      connectedServices: null,
      purpose,
      expiresAt,
    });

    // If the caller is the owner (private network or API key), auto-approve immediately.
    const identity = c.get("identity");
    if (identity?.isOwner) {
      await autoApproveHandoff(db, handoffId, purpose);
    }

    return c.json({
      handoffId,
      authUrl: new URL(`/api/handoff/${handoffId}`, config.baseUrl).toString(),
    });
  });

  /**
   * GET /api/handoff/:id
   * Serves the handoff HTML page.
   *
   * Local mode + private network: auto-approves and shows success.
   * Central mode / public: requires login → shows approve page.
   */
  app.get("/:id", async (c) => {
    const handoffId = c.req.param("id");
    const config = getConfig();

    if (!/^[0-9a-f]{64}$/.test(handoffId)) {
      return c.html("<h1>Invalid handoff ID</h1>", 400);
    }

    const [handoff] = await db
      .select()
      .from(handoffs)
      .where(eq(handoffs.id, handoffId))
      .limit(1);

    if (!handoff) {
      return c.html("<h1>Handoff not found or expired</h1>", 404);
    }

    if (handoff.expiresAt < new Date()) {
      await db.delete(handoffs).where(eq(handoffs.id, handoffId));
      return c.html("<h1>Handoff expired</h1>", 410);
    }

    // Already completed — show success
    if (handoff.status !== "pending") {
      const layout = await readView("layout.html");
      const html = layout
        .replace("{{title}}", "Aionima ID — Handoff Complete")
        .replace("{{content}}", `
          <div style="text-align:center;padding:3rem">
            <h2>Handoff approved</h2>
            <p style="color:#888">You can close this window.</p>
          </div>
        `);
      return c.html(html);
    }

    // Private network owner: auto-approve without login
    const identity = c.get("identity");
    if (identity?.isOwner) {
      await autoApproveHandoff(db, handoffId, handoff.purpose);

      const layout = await readView("layout.html");
      const html = layout
        .replace("{{title}}", "Aionima ID — Handoff Approved")
        .replace("{{content}}", `
          <div style="text-align:center;padding:3rem">
            <h2 style="color:#4ade80">Approved</h2>
            <p style="color:#888">Private network identity verified. You can close this window.</p>
            <script>setTimeout(function(){ window.close(); }, 1500);</script>
          </div>
        `);
      return c.html(html);
    }

    // Central mode / non-private: require login
    const user = c.get("user");
    const providerFilter = purposeToProviderFilter(handoff.purpose);

    let pageContent: string;

    if (!user) {
      const loginHtml = await readView("login.html");
      pageContent = loginHtml.replace("{{handoff_id}}", escapeHtml(handoffId));
    } else {
      let userConnections = await db
        .select()
        .from(connections)
        .where(eq(connections.userId, user.id));

      if (providerFilter) {
        userConnections = userConnections.filter((conn) =>
          providerFilter.includes(conn.provider),
        );
      }

      // OAuth providers are managed by Hive-ID — no local connect buttons.
      const connList = userConnections
        .map(
          (conn) => `
          <div class="conn-item">
            <span class="provider">${escapeHtml(conn.provider)}</span>
            <span class="role badge">${escapeHtml(conn.role)}</span>
            <span class="label">${escapeHtml(conn.accountLabel ?? "(no label)")}</span>
          </div>`,
        )
        .join("\n");

      const connectButtons = "";

      const approveHtml = await readView("handoff-approve.html");
      pageContent = approveHtml
        .replace("{{handoff_id}}", escapeHtml(handoffId))
        .replace("{{user_email}}", escapeHtml(user.email))
        .replace(
          "{{connections_list}}",
          connList || "<p>No connected services yet.</p>",
        )
        .replace("{{connect_buttons}}", connectButtons);
    }

    const layout = await readView("layout.html");
    const html = layout
      .replace("{{title}}", "Aionima ID — Handoff")
      .replace("{{content}}", pageContent);

    return c.html(html);
  });

  /**
   * POST /api/handoff/:id/approve
   * Central mode: requires session. Snapshots tokens into handoff.
   * Local mode: accepts owner identity (private network or API key).
   */
  app.post("/:id/approve", async (c) => {
    const config = getConfig();
    const user = c.get("user");
    const identity = c.get("identity");

    // Accept owner identity (private network or API key) without session
    const isOwnerAuthed = identity?.isOwner;

    if (!user && !isOwnerAuthed) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const handoffId = c.req.param("id");

    const [handoff] = await db
      .select()
      .from(handoffs)
      .where(eq(handoffs.id, handoffId))
      .limit(1);

    if (!handoff) {
      return c.json({ error: "Handoff not found" }, 404);
    }

    if (handoff.expiresAt < new Date()) {
      await db.delete(handoffs).where(eq(handoffs.id, handoffId));
      return c.json({ error: "Handoff expired" }, 410);
    }

    if (handoff.status !== "pending") {
      return c.json({ error: "Handoff already used" }, 409);
    }

    if (user) {
      // Session-based approval — snapshot user's connections
      await approveWithUserConnections(db, handoffId, handoff.purpose, user.id);
    } else {
      // Owner auto-approval — snapshot all connections (or empty)
      await autoApproveHandoff(db, handoffId, handoff.purpose);
    }

    return c.json({ success: true });
  });

  /**
   * GET /api/handoff/:id/poll
   * No auth required — the 256-bit handoff ID is the auth.
   * Returns tokens ONCE, then deletes the handoff.
   */
  app.get("/:id/poll", async (c) => {
    const handoffId = c.req.param("id");

    if (!/^[0-9a-f]{64}$/.test(handoffId)) {
      return c.json({ status: "not_found" }, 404);
    }

    const [handoff] = await db
      .select()
      .from(handoffs)
      .where(eq(handoffs.id, handoffId))
      .limit(1);

    if (!handoff) {
      return c.json({ status: "not_found" }, 404);
    }

    if (handoff.expiresAt < new Date()) {
      await db.delete(handoffs).where(eq(handoffs.id, handoffId));
      return c.json({ status: "expired" });
    }

    if (handoff.status === "pending") {
      return c.json({ status: "pending" });
    }

    if (handoff.status === "authenticated" && handoff.connectedServices) {
      const userInfo = handoff.purpose === "dashboard-login"
        ? await resolveHandoffUserInfo(db, handoff.userId)
        : undefined;

      await db.delete(handoffs).where(eq(handoffs.id, handoffId));

      const services = JSON.parse(decrypt(handoff.connectedServices)) as ConnectionSnapshot[];

      return c.json({
        status: "completed",
        services: services.map((s) => ({
          provider: s.provider,
          role: s.role,
          accountLabel: s.accountLabel,
          accessToken: s.accessToken,
          refreshToken: s.refreshToken,
        })),
        ...(userInfo ? { user: userInfo } : {}),
      });
    }

    // "authenticated" but no connectedServices — local mode empty approval
    if (handoff.status === "authenticated") {
      const userInfo = handoff.purpose === "dashboard-login"
        ? await resolveHandoffUserInfo(db, handoff.userId)
        : undefined;

      await db.delete(handoffs).where(eq(handoffs.id, handoffId));
      return c.json({ status: "completed", services: [], ...(userInfo ? { user: userInfo } : {}) });
    }

    return c.json({ status: handoff.status });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Approve a handoff by snapshotting a specific user's connections.
 */
async function approveWithUserConnections(
  db: DrizzleDb,
  handoffId: string,
  purpose: string | null,
  userId: string,
): Promise<void> {
  let userConnections = await db
    .select()
    .from(connections)
    .where(eq(connections.userId, userId));

  const providerFilter = purposeToProviderFilter(purpose);
  if (providerFilter) {
    userConnections = userConnections.filter((conn) =>
      providerFilter.includes(conn.provider),
    );
  }

  const snapshot: ConnectionSnapshot[] = userConnections.map((conn) => ({
    provider: conn.provider,
    role: conn.role,
    accountLabel: conn.accountLabel,
    accessToken: conn.accessToken ? decrypt(conn.accessToken) : null,
    refreshToken: conn.refreshToken ? decrypt(conn.refreshToken) : null,
  }));

  const encryptedSnapshot = encrypt(JSON.stringify(snapshot));

  await db
    .update(handoffs)
    .set({
      userId,
      status: "authenticated",
      connectedServices: encryptedSnapshot,
    })
    .where(eq(handoffs.id, handoffId));
}

/**
 * Resolve the authenticated user's entity info for a dashboard-login handoff.
 * If handoffUserId is set, looks up that user's linked entity.
 * Otherwise falls back to the genesis owner entity (#E0) for local mode auto-approvals.
 */
async function resolveHandoffUserInfo(
  db: DrizzleDb,
  handoffUserId: string | null,
): Promise<{ userId: string; entityId: string; displayName: string; coaAlias: string; geid: string; role: string } | undefined> {
  if (handoffUserId) {
    // Session-based: look up user → entity
    const [user] = await db.select().from(users).where(eq(users.id, handoffUserId)).limit(1);
    if (!user || !user.entityId) return undefined;

    const [entity] = await db.select().from(entities).where(eq(entities.id, user.entityId)).limit(1);
    if (!entity) return undefined;

    const [geid] = await db.select().from(geidLocal).where(eq(geidLocal.entityId, entity.id)).limit(1);

    return {
      userId: user.id,
      entityId: entity.id,
      displayName: entity.displayName,
      coaAlias: entity.coaAlias,
      geid: geid?.geid ?? "",
      role: user.dashboardRole ?? "viewer",
    };
  }

  // No userId — local mode owner auto-approval. Find #E0 (genesis owner).
  const [ownerEntity] = await db.select().from(entities).where(eq(entities.coaAlias, "#E0")).limit(1);
  if (!ownerEntity) return undefined;

  const [geid] = await db.select().from(geidLocal).where(eq(geidLocal.entityId, ownerEntity.id)).limit(1);

  // Find the user linked to this entity (if any)
  const [ownerUser] = ownerEntity.userId
    ? await db.select().from(users).where(eq(users.id, ownerEntity.userId)).limit(1)
    : [undefined];

  return {
    userId: ownerUser?.id ?? ownerEntity.id,
    entityId: ownerEntity.id,
    displayName: ownerEntity.displayName,
    coaAlias: ownerEntity.coaAlias,
    geid: geid?.geid ?? "",
    role: ownerUser?.dashboardRole ?? "admin",
  };
}

/**
 * Auto-approve a handoff for the owner (local mode, no specific user).
 * Snapshots ALL connections in the database (the local ID service is single-tenant).
 */
async function autoApproveHandoff(
  db: DrizzleDb,
  handoffId: string,
  purpose: string | null,
): Promise<void> {
  // Local ID service is single-tenant — grab all connections
  let allConnections = await db.select().from(connections);

  const providerFilter = purposeToProviderFilter(purpose);
  if (providerFilter) {
    allConnections = allConnections.filter((conn) =>
      providerFilter.includes(conn.provider),
    );
  }

  if (allConnections.length === 0) {
    // No OAuth connections — still approve (identity is established via network)
    await db
      .update(handoffs)
      .set({ status: "authenticated", connectedServices: null })
      .where(eq(handoffs.id, handoffId));
    return;
  }

  const snapshot: ConnectionSnapshot[] = allConnections.map((conn) => ({
    provider: conn.provider,
    role: conn.role,
    accountLabel: conn.accountLabel,
    accessToken: conn.accessToken ? decrypt(conn.accessToken) : null,
    refreshToken: conn.refreshToken ? decrypt(conn.refreshToken) : null,
  }));

  const encryptedSnapshot = encrypt(JSON.stringify(snapshot));

  await db
    .update(handoffs)
    .set({ status: "authenticated", connectedServices: encryptedSnapshot })
    .where(eq(handoffs.id, handoffId));
}
