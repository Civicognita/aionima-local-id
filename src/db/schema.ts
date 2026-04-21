/**
 * Local-ID schema shim — re-exports every table + enum from the bundled
 * @agi/db-schema at `./schema/`, plus legacy name aliases and type aliases so
 * existing imports in this repo don't need to churn.
 *
 * **Do not author schema here.** Schema lives in @agi/db-schema (synced via
 * `pnpm sync:schema` — see ./schema/README.md).
 *
 * Legacy aliases:
 * - `sessions` → `authSessions` (the shared schema splits auth_sessions from
 *   the compliance-trail revocation_audit; Local-ID only needs the former).
 */

// Re-export everything first so the new names are available.
export * from "./schema/index.js";

import {
  authSessions,
  entities,
  geidLocal,
  connections,
  handoffs,
  users,
  agentBindings,
  registrations,
} from "./schema/index.js";

// ---------------------------------------------------------------------------
// Legacy table alias — callers still import `sessions` from this file.
// ---------------------------------------------------------------------------

export { authSessions as sessions };

// ---------------------------------------------------------------------------
// Legacy type aliases — preserve the old `EntityRecord`/`Session`/etc. names.
// ---------------------------------------------------------------------------

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof authSessions.$inferSelect;
export type NewSession = typeof authSessions.$inferInsert;
export type Connection = typeof connections.$inferSelect;
export type NewConnection = typeof connections.$inferInsert;
export type Handoff = typeof handoffs.$inferSelect;
export type NewHandoff = typeof handoffs.$inferInsert;
export type EntityRecord = typeof entities.$inferSelect;
export type NewEntity = typeof entities.$inferInsert;
export type GeidLocalRecord = typeof geidLocal.$inferSelect;
export type AgentBinding = typeof agentBindings.$inferSelect;
export type Registration = typeof registrations.$inferSelect;
