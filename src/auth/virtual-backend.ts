/**
 * Virtual-user auth backend — argon2-verifies `users.password_hash`.
 *
 * This is the default backend and matches Local-ID's pre-Phase-3
 * behavior. Every row with `auth_backend='virtual'` is owned here; the
 * `password_hash` column is the source of truth for that principal's
 * secret.
 */

import { verify } from "@node-rs/argon2";
import type { DrizzleDb } from "../db/client.js";
import type {
  AuthBackend,
  AuthCredentials,
  AuthResult,
  AuthUserProfile,
} from "./backend.js";
import { AuthBackendRegistry } from "./backend.js";

export class VirtualAuthBackend implements AuthBackend {
  readonly id = "virtual" as const;

  constructor(
    private readonly db: DrizzleDb,
    private readonly registry: AuthBackendRegistry,
  ) {}

  async lookup(principal: string): Promise<AuthUserProfile | null> {
    return this.registry.findProfile("virtual", principal);
  }

  async authenticate(
    principal: string,
    creds: AuthCredentials,
  ): Promise<AuthResult> {
    // We lookup via the shared registry helper so email / username /
    // principal all match the same way auth.ts did before Phase 3.
    const profile = await this.registry.findProfileByPrincipal(principal);
    if (!profile || profile.authBackend !== "virtual") {
      return { ok: false, reason: "unknown_principal" };
    }

    // Re-select the row to get password_hash (registry helper strips it).
    const hash = await this.fetchHash(profile.id);
    if (!hash) {
      return { ok: false, reason: "invalid_credentials" };
    }
    const matched = await verify(hash, creds.password);
    if (!matched) {
      return { ok: false, reason: "invalid_credentials" };
    }
    return { ok: true, profile };
  }

  private async fetchHash(userId: string): Promise<string | null> {
    const { users } = await import("../db/schema/index.js");
    const { eq } = await import("drizzle-orm");
    const [row] = await this.db
      .select({ passwordHash: users.passwordHash })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    return row?.passwordHash ?? null;
  }
}
