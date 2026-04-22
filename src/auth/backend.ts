/**
 * Pluggable authentication backend abstraction (Phase 3 — tynn #269).
 *
 * Local-ID supports multiple auth backends alongside the default virtual
 * (password_hash) backend: PAM for system users on the host, LDAP and
 * Active Directory for enterprise deployments. All backends plug into
 * the same interface so routes that authenticate a user don't care which
 * backend owns them.
 *
 * Dispatch key: the `users.auth_backend` enum column on the shared
 * schema. A lookup row tells us which backend to call for credential
 * verification — credentials themselves never live in the `users` table
 * (except for virtual users, which keep `password_hash` locally).
 */

import { eq, and } from "drizzle-orm";
import type { DrizzleDb } from "../db/client.js";
import { users } from "../db/schema/index.js";

/** Discriminator for which backend owns a given principal. */
export type AuthBackendId = "virtual" | "pam" | "ldap" | "ad";

/**
 * The minimum set of user fields Local-ID needs after a successful
 * authentication. The row that ultimately owns this information is the
 * `users` profile row, keyed on `(auth_backend, principal)`.
 */
export interface AuthUserProfile {
  id: string;
  authBackend: AuthBackendId;
  principal: string;
  email: string | null;
  username: string | null;
  displayName: string | null;
  entityId: string | null;
  dashboardRole: string;
}

export interface AuthCredentials {
  /** Plaintext password supplied by the user — memory-scoped, never persisted. */
  password: string;
}

export type AuthResult =
  | { ok: true; profile: AuthUserProfile }
  | { ok: false; reason: "invalid_credentials" | "unknown_principal" | "backend_unavailable" };

/**
 * Every auth backend exposes the same surface. `authenticate` is the
 * hot path (called on every login); `lookup` is used by the profile
 * repurpose work (#271) to find the row that owns a principal without
 * verifying credentials.
 */
export interface AuthBackend {
  readonly id: AuthBackendId;

  /** Verify that `principal` + `creds` match. */
  authenticate(principal: string, creds: AuthCredentials): Promise<AuthResult>;

  /**
   * Fetch the profile row for a principal without verifying credentials.
   * Returns null if this backend doesn't own the principal.
   */
  lookup(principal: string): Promise<AuthUserProfile | null>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Routes hold a single `AuthBackendRegistry`. On login:
 *   1. Look up the user row by (auth_backend, principal)
 *   2. Dispatch to the matching backend
 *   3. Return the profile (or reject)
 *
 * New backends get registered via `register()` at server startup.
 */
export class AuthBackendRegistry {
  private readonly backends = new Map<AuthBackendId, AuthBackend>();

  constructor(private readonly db: DrizzleDb) {}

  register(backend: AuthBackend): void {
    this.backends.set(backend.id, backend);
  }

  list(): AuthBackendId[] {
    return [...this.backends.keys()];
  }

  /**
   * Resolve `principal` by scanning every registered backend in priority
   * order: the `users` profile row is the source of truth, so we consult
   * it first and dispatch to the named backend. If no profile row exists,
   * we fall through and try each backend's own `lookup()` — this is how
   * PAM users get their profile row auto-created on first login.
   */
  async authenticate(
    principal: string,
    creds: AuthCredentials,
  ): Promise<AuthResult> {
    const profile = await this.findProfileByPrincipal(principal);
    if (profile) {
      const backend = this.backends.get(profile.authBackend);
      if (!backend) return { ok: false, reason: "backend_unavailable" };
      return backend.authenticate(principal, creds);
    }
    // No profile row yet — try each backend in registration order. First
    // match wins. Lets PAM/LDAP users appear without a manual profile
    // insert.
    for (const backend of this.backends.values()) {
      const discovered = await backend.lookup(principal);
      if (discovered) {
        return backend.authenticate(principal, creds);
      }
    }
    return { ok: false, reason: "unknown_principal" };
  }

  /**
   * Shared profile lookup — callers use this to resolve which backend a
   * principal belongs to before dispatching other operations (e.g. sign
   * out, rotate).
   */
  async findProfileByPrincipal(
    principal: string,
  ): Promise<AuthUserProfile | null> {
    const normalized = principal.toLowerCase();
    // Search order: username, email, then exact principal match.
    const candidates = [
      await this.db.select().from(users).where(eq(users.username, normalized)).limit(1),
      await this.db.select().from(users).where(eq(users.email, normalized)).limit(1),
      await this.db.select().from(users).where(eq(users.principal, normalized)).limit(1),
    ];
    for (const [row] of candidates) {
      if (row) return toProfile(row);
    }
    return null;
  }

  /** Lookup the profile when you already know (backend, principal). */
  async findProfile(
    authBackend: AuthBackendId,
    principal: string,
  ): Promise<AuthUserProfile | null> {
    const [row] = await this.db
      .select()
      .from(users)
      .where(and(eq(users.authBackend, authBackend), eq(users.principal, principal.toLowerCase())))
      .limit(1);
    return row ? toProfile(row) : null;
  }
}

function toProfile(row: typeof users.$inferSelect): AuthUserProfile {
  return {
    id: row.id,
    authBackend: row.authBackend as AuthBackendId,
    principal: row.principal,
    email: row.email,
    username: row.username,
    displayName: row.displayName,
    entityId: row.entityId,
    dashboardRole: row.dashboardRole,
  };
}
