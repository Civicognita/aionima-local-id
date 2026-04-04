/**
 * Network Identity — authentication for local/federated ID service.
 *
 * Three auth tiers, checked in order:
 *
 * 1. **Private network auto-IDENT** — requests from RFC 1918 addresses are
 *    automatically identified as the node owner. No login required.
 *    The network IS the credential on a private LAN.
 *
 * 2. **Node API key** — machine-to-machine auth between the AGI gateway and
 *    the local ID service. The gateway sends `Authorization: Bearer <apiKey>`.
 *
 * 3. **Mycelium-Sig (federation)** — HIVE peers authenticate via Ed25519
 *    signed requests. Each request carries a self-authenticating signature
 *    over the node ID, timestamp, and body hash. No sessions or cookies.
 *
 * OAuth (Google/GitHub/Discord) remains available as an optional add-on for
 * connecting external services — it is NOT required for local identity.
 */

import { createHash, createPublicKey, verify } from "node:crypto";
import type { Context, Next } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { AuthEnv } from "./middleware.js";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Private network detection
// ---------------------------------------------------------------------------

function extractIp(c: Context): string {
  // Reverse proxy header takes precedence (Caddy sets this)
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0];
    return first !== undefined ? first.trim() : "unknown";
  }
  // Fall back to Hono's Node.js connection info (raw socket address)
  try {
    const info = getConnInfo(c);
    return info.remote?.address ?? "unknown";
  } catch {
    return "unknown";
  }
}

function isPrivateIp(ip: string): boolean {
  // Loopback
  if (ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1") return true;

  // Strip IPv6 mapped prefix
  const v4 = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  const parts = v4.split(".").map(Number);
  if (parts.length === 4) {
    if (parts[0] === 10) return true;                                    // 10.0.0.0/8
    if (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true;              // 192.168.0.0/16
  }
  if (ip.startsWith("fe80:")) return true; // Link-local IPv6

  return false;
}

// ---------------------------------------------------------------------------
// Mycelium-Sig verification
// ---------------------------------------------------------------------------

interface SigVerifyResult {
  nodeId: string;
  timestamp: number;
  valid: boolean;
}

/**
 * Parse and verify a Mycelium-Sig header.
 * Format: Mycelium-Sig ed25519 <nodeId>.<timestamp>.<signatureHex>
 *
 * The signature covers: <nodeId>.<timestamp>.<bodyHash>
 * where bodyHash is SHA-256 of the request body (or empty string for GET).
 */
function verifyMyceliumSig(
  header: string,
  bodyHash: string,
  resolvePublicKey: (nodeId: string) => string | null,
  maxAgeSeconds = 300,
): SigVerifyResult | null {
  const match = header.match(/^Mycelium-Sig ed25519 ([^.]+)\.(\d+)\.([a-f0-9]+)$/);
  if (!match) return null;

  const [, nodeId, timestampStr, signatureHex] = match;
  if (!nodeId || !timestampStr || !signatureHex) return null;

  const timestamp = parseInt(timestampStr, 10);
  const now = Math.floor(Date.now() / 1000);

  // Replay window check — 5 minute window by default
  if (Math.abs(now - timestamp) > maxAgeSeconds) {
    return { nodeId, timestamp, valid: false };
  }

  const publicKeyBase64 = resolvePublicKey(nodeId);
  if (!publicKeyBase64) return { nodeId, timestamp, valid: false };

  try {
    const spkiDer = Buffer.from(publicKeyBase64, "base64");
    const pubKey = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    const payload = `${nodeId}.${timestamp}.${bodyHash}`;
    const sig = Buffer.from(signatureHex, "hex");
    const valid = verify(null, Buffer.from(payload), pubKey, sig);
    return { nodeId, timestamp, valid };
  } catch {
    return { nodeId, timestamp, valid: false };
  }
}

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Auth identity types
// ---------------------------------------------------------------------------

export type IdentitySource = "private-network" | "node-api-key" | "mycelium-sig" | "session" | "anonymous";

export interface NetworkIdentity {
  /** How this identity was established. */
  source: IdentitySource;
  /** Whether this identity is the node owner. */
  isOwner: boolean;
  /** Node ID if authenticated via federation. */
  nodeId?: string;
  /** Resolved user ID (if mapped to a local user). */
  userId?: string;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Callback to resolve a peer node's public key by its node ID.
 * In production, this queries the geid_registry or node_registry table.
 */
export type PeerKeyResolver = (nodeId: string) => string | null;

/** In-memory peer key cache, populated from DB on boot. */
let _peerKeyResolver: PeerKeyResolver = () => null;

export function setPeerKeyResolver(resolver: PeerKeyResolver): void {
  _peerKeyResolver = resolver;
}

/**
 * Network identity middleware for local/federated mode.
 *
 * Runs AFTER the Lucia session middleware. If Lucia already identified the
 * user (cookie session), this middleware upgrades the identity with source info
 * but doesn't override it. For unauthenticated requests, it checks:
 *
 * 1. Private network → auto-IDENT as owner
 * 2. Bearer token → node API key
 * 3. Mycelium-Sig header → federated peer
 */
export function networkIdentityMiddleware() {
  return async (c: Context<AuthEnv & { Variables: { identity?: NetworkIdentity } }>, next: Next) => {
    const config = getConfig();
    const existingUser = c.get("user");

    // If already authenticated via session, tag it and continue
    if (existingUser) {
      c.set("identity", {
        source: "session",
        isOwner: true, // Session users on local mode are always the owner
        userId: existingUser.id,
      } satisfies NetworkIdentity);
      return next();
    }

    // --- Tier 1: Private network auto-IDENT ---
    if (true) {
      const ip = extractIp(c);
      if (isPrivateIp(ip)) {
        c.set("identity", {
          source: "private-network",
          isOwner: true,
        } satisfies NetworkIdentity);
        return next();
      }
    }

    // --- Tier 2: Node API key (Bearer token) ---
    const authHeader = c.req.header("authorization");
    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      if (config.ownerNode.apiKey && token === config.ownerNode.apiKey) {
        c.set("identity", {
          source: "node-api-key",
          isOwner: true,
        } satisfies NetworkIdentity);
        return next();
      }
    }

    // --- Tier 3: Mycelium-Sig (federation) ---
    const sigHeader = c.req.header("mycelium-sig");
    if (sigHeader) {
      // For GET requests, body hash is empty string hash
      const body = c.req.method === "GET" ? "" : await c.req.text();
      const bodyHash = sha256(body);

      const result = verifyMyceliumSig(sigHeader, bodyHash, _peerKeyResolver);
      if (result?.valid) {
        c.set("identity", {
          source: "mycelium-sig",
          isOwner: false,
          nodeId: result.nodeId,
        } satisfies NetworkIdentity);
        return next();
      }
    }

    // --- No identity established ---
    c.set("identity", {
      source: "anonymous",
      isOwner: false,
    } satisfies NetworkIdentity);

    return next();
  };
}

/**
 * Guard: require owner identity (private network, API key, or session).
 */
export function requireOwner() {
  return async (c: Context<AuthEnv & { Variables: { identity?: NetworkIdentity } }>, next: Next) => {
    const identity = c.get("identity");
    if (!identity?.isOwner) {
      return c.json({ error: "Owner authentication required" }, 401);
    }
    return next();
  };
}

/**
 * Guard: require any valid identity (owner OR federated peer).
 */
export function requireIdentity() {
  return async (c: Context<AuthEnv & { Variables: { identity?: NetworkIdentity } }>, next: Next) => {
    const identity = c.get("identity");
    if (!identity || identity.source === "anonymous") {
      return c.json({ error: "Authentication required" }, 401);
    }
    return next();
  };
}
