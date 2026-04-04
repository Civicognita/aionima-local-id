/**
 * Periodic cleanup of expired handoff sessions.
 * Runs every 5 minutes, deletes handoffs past their expiresAt.
 */

import { lt } from "drizzle-orm";
import type { DrizzleDb } from "../db/client.js";
import { handoffs } from "../db/schema.js";

export function startHandoffCleanup(db: DrizzleDb): void {
  const INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  const cleanup = async () => {
    try {
      await db
        .delete(handoffs)
        .where(lt(handoffs.expiresAt, new Date()));
    } catch (e) {
      console.error("[cleanup] Failed to purge expired handoffs:", e);
    }
  };

  // Run once on startup, then every 5 minutes
  cleanup();
  setInterval(cleanup, INTERVAL_MS).unref();
}
