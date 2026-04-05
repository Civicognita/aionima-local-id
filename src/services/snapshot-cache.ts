/**
 * Snapshot Cache — periodic fetch of the Hive-ID GEID registry snapshot.
 *
 * Local-ID uses this cache for offline-capable federation verification.
 * If Hive-ID is unreachable, the cache returns stale data or null — the
 * service continues working for all local features regardless.
 */

import { createHash } from "node:crypto";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GeidEntry {
  publicKey: string;
  homeNodeUrl: string;
  displayName: string;
  trustTier: string;
}

interface TrustCert {
  tier: string;
  issuedBy: string;
  issuedAt: string;
}

interface CachedSnapshot {
  geids: Map<string, GeidEntry>;
  trustCerts: Map<string, TrustCert[]>;
  fetchedAt: number;
  contentHash: string;
}

// ---------------------------------------------------------------------------
// Singleton cache
// ---------------------------------------------------------------------------

let cache: CachedSnapshot | null = null;

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

export async function refreshSnapshotCache(): Promise<void> {
  const config = getConfig();
  const snapshotUrl = `${config.hiveIdUrl}/snapshots/registry-latest.json`;

  try {
    const res = await fetch(snapshotUrl, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) {
      console.warn(`[snapshot-cache] Failed to fetch snapshot: ${res.status}`);
      return;
    }

    const data = await res.json() as {
      geids?: Array<{ geid: string } & GeidEntry>;
      trustCerts?: Array<{ geid: string } & TrustCert>;
      contentHash?: string;
    };

    // Verify content hash if present
    const hashInput = JSON.stringify({ ...data, contentHash: undefined });
    const expectedHash = createHash("sha256").update(hashInput).digest("hex");
    if (data.contentHash && data.contentHash !== expectedHash) {
      console.warn("[snapshot-cache] Snapshot content hash mismatch — possible tampering");
      return;
    }

    // Build lookup maps
    const geids = new Map<string, GeidEntry>();
    for (const entry of data.geids ?? []) {
      geids.set(entry.geid, {
        publicKey: entry.publicKey,
        homeNodeUrl: entry.homeNodeUrl,
        displayName: entry.displayName,
        trustTier: entry.trustTier,
      });
    }

    const trustCerts = new Map<string, TrustCert[]>();
    for (const cert of data.trustCerts ?? []) {
      const existing = trustCerts.get(cert.geid) ?? [];
      existing.push({ tier: cert.tier, issuedBy: cert.issuedBy, issuedAt: cert.issuedAt });
      trustCerts.set(cert.geid, existing);
    }

    cache = { geids, trustCerts, fetchedAt: Date.now(), contentHash: data.contentHash ?? "" };
    console.log(`[snapshot-cache] Refreshed: ${geids.size} GEIDs, ${trustCerts.size} trust entries`);
  } catch (err) {
    console.warn(`[snapshot-cache] Fetch failed: ${err instanceof Error ? err.message : err}`);
  }
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

export function lookupGeid(geid: string): GeidEntry | null {
  return cache?.geids.get(geid) ?? null;
}

export function lookupTrust(geid: string): TrustCert[] | null {
  return cache?.trustCerts.get(geid) ?? null;
}

export function getSnapshotAge(): number | null {
  return cache ? Date.now() - cache.fetchedAt : null;
}

// ---------------------------------------------------------------------------
// Background refresh
// ---------------------------------------------------------------------------

export function startSnapshotRefresh(intervalMs: number = 300_000): { stop: () => void } {
  // Fire immediately on start (non-blocking — failure is logged, not thrown)
  refreshSnapshotCache().catch(() => {});

  const timer = setInterval(() => refreshSnapshotCache().catch(() => {}), intervalMs);
  // Allow the process to exit without waiting for the timer
  timer.unref();

  return { stop: () => clearInterval(timer) };
}
