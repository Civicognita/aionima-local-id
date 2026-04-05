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
 * The local snapshot cache is checked first for offline-capable verification.
 */

import { Hono } from "hono";
import { getConfig } from "../../config.js";
import { lookupGeid, lookupTrust } from "../../services/snapshot-cache.js";
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
   * Verify a GEID or node identity. Checks the local Hive-ID snapshot cache
   * first — if the GEID is cached, returns the result immediately without
   * reaching out to Hive-ID (offline-capable). Falls back to a Hive-ID redirect
   * hint when the GEID is not in the local cache.
   */
  app.post("/verify", async (c) => {
    const body = await c.req.json().catch(() => ({})) as { geid?: string; nodeId?: string };
    const config = getConfig();

    if (body.geid) {
      // Check local snapshot cache first (offline-capable)
      const cached = lookupGeid(body.geid);
      if (cached) {
        const trust = lookupTrust(body.geid) ?? [];
        return c.json({
          geid: body.geid,
          known: true,
          source: "snapshot-cache",
          publicKey: cached.publicKey,
          homeNodeUrl: cached.homeNodeUrl,
          displayName: cached.displayName,
          trustTier: cached.trustTier,
          trustCerts: trust,
        });
      }

      // Not in cache — direct caller to Hive-ID for authoritative lookup
      return c.json({
        geid: body.geid,
        known: false,
        source: "local",
        hint: "GEID not in local snapshot cache. Query the HIVE registry for authoritative lookup.",
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

  return {
    schema: "mycelium-node-v1",
    service: "aionima-local-id",
    mode: "local",
    url: config.baseUrl,
    capabilities: {
      oauth: false,
      handoff: true,
      federation: true,
    },
    federation: {
      verifyEndpoint: `${config.baseUrl}/federation/verify`,
      whoamiEndpoint: `${config.baseUrl}/federation/whoami`,
    },
    // OAuth providers are managed by Hive-ID, not this local node
    providers: [],
  };
}
