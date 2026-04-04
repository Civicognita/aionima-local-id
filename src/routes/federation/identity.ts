/**
 * Federation Identity Routes — self-describing endpoints for the local node.
 *
 * These routes let other nodes discover and verify this ID service's identity:
 *
 * - /.well-known/mycelium-node.json — node manifest (who am I, what can I do)
 * - /federation/verify — verify a node's identity against this service
 * - /federation/whoami — return the caller's resolved identity
 *
 * This is a local-only service. The node manifest always advertises mode "local".
 * For global GEID lookups, callers should query the public Hive-ID service.
 */

import { Hono } from "hono";
import { getConfig } from "../../config.js";
import type { NetworkIdentity } from "../../auth/network-identity.js";

// Augmented context type — network identity is set by middleware
type FedEnv = { Variables: { identity?: NetworkIdentity } };

export function federationIdentityRoutes() {
  const app = new Hono<FedEnv>();

  /**
   * GET /federation/whoami
   * Returns the caller's resolved identity — useful for debugging auth.
   */
  app.get("/whoami", (c) => {
    const identity = c.get("identity");
    if (!identity || identity.source === "anonymous") {
      return c.json({
        identified: false,
        source: identity?.source ?? "anonymous",
        hint: "Send a Mycelium-Sig header, Bearer token, or access from a private network",
      });
    }

    return c.json({
      identified: true,
      source: identity.source,
      isOwner: identity.isOwner,
      nodeId: identity.nodeId ?? null,
    });
  });

  /**
   * POST /federation/verify
   * Verify a GEID or node identity. Any node can ask "is this GEID registered?"
   * Central mode checks the geid_registry; local mode only knows about itself.
   */
  app.post("/verify", async (c) => {
    const body = await c.req.json().catch(() => ({})) as { geid?: string; nodeId?: string };
    const config = getConfig();

    if (body.geid) {
      // Local-ID only knows its own node — delegate global lookups to Hive-ID.
      return c.json({
        geid: body.geid,
        known: false,
        hint: "Local ID service only knows its own node. Query the HIVE registry for global lookups.",
        hiveIdUrl: config.hiveIdUrl,
      });
    }

    return c.json({ error: "Provide geid or nodeId to verify" }, 400);
  });

  return app;
}

/**
 * Build the /.well-known/mycelium-node.json manifest.
 * This is NOT a Hono sub-app — it returns JSON directly so we can mount
 * it at the exact well-known path.
 */
export function buildNodeManifest(): Record<string, unknown> {
  const config = getConfig();

  const capabilities: Record<string, boolean> = {
    oauth: Object.values(config.providers).some((p) => p !== null),
    handoff: true,
    federation: true,
  };

  return {
    schema: "mycelium-node-v1",
    service: "aionima-local-id",
    mode: "local",
    url: config.baseUrl,
    capabilities,
    federation: {
      verifyEndpoint: `${config.baseUrl}/federation/verify`,
      whoamiEndpoint: `${config.baseUrl}/federation/whoami`,
    },
    providers: Object.entries(config.providers)
      .filter(([, v]) => v !== null)
      .map(([k]) => k),
  };
}
