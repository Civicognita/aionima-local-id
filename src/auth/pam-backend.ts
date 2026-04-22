/**
 * PAM (Pluggable Authentication Modules) auth backend — tynn #270.
 *
 * Verifies credentials against the host's system auth (`/etc/passwd` +
 * `/etc/shadow` via PAM). Used for AGI installs where "users" are
 * system users, not virtual rows in the DB. Implementation uses a
 * subprocess helper (`helpers/pam_auth.sh`) that runs with the narrow
 * permissions needed to consult PAM — this avoids pulling a native
 * Node addon into the image and keeps the attack surface small.
 *
 * **Deployment prerequisite:** the helper script must be installed
 * suid-root OR the agi-local-id container must run with a sidecar
 * that owns PAM consultation. See docs/human/auth-pam.md for setup.
 *
 * Until that helper ships, `authenticate()` returns `backend_unavailable`
 * with a clear reason so callers / Phase 3 tests can detect the gap.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { DrizzleDb } from "../db/client.js";
import { users } from "../db/schema/index.js";
import type {
  AuthBackend,
  AuthCredentials,
  AuthResult,
  AuthUserProfile,
} from "./backend.js";
import { AuthBackendRegistry } from "./backend.js";
import { nanoid } from "nanoid";

const DEFAULT_HELPER_PATH = "/opt/agi-local-id/helpers/pam_auth.sh";

export interface PamBackendOptions {
  /** Path to the helper script. Override for tests / alternate deployments. */
  helperPath?: string;
  /** Profile auto-provision on first login — default true. */
  autoProvision?: boolean;
}

export class PamAuthBackend implements AuthBackend {
  readonly id = "pam" as const;
  private readonly helperPath: string;
  private readonly autoProvision: boolean;

  constructor(
    private readonly db: DrizzleDb,
    private readonly registry: AuthBackendRegistry,
    opts: PamBackendOptions = {},
  ) {
    this.helperPath = opts.helperPath ?? DEFAULT_HELPER_PATH;
    this.autoProvision = opts.autoProvision !== false;
  }

  async lookup(principal: string): Promise<AuthUserProfile | null> {
    // PAM users are identified by their system username. We only resolve
    // via the user's profile row if one already exists — discovery of
    // previously-unseen system users happens inside `authenticate`.
    return this.registry.findProfile("pam", principal);
  }

  async authenticate(
    principal: string,
    creds: AuthCredentials,
  ): Promise<AuthResult> {
    if (!existsSync(this.helperPath)) {
      return { ok: false, reason: "backend_unavailable" };
    }

    const ok = await runPamHelper(this.helperPath, principal, creds.password);
    if (!ok) {
      return { ok: false, reason: "invalid_credentials" };
    }

    // Successful PAM auth — get or create the profile row.
    let profile = await this.registry.findProfile("pam", principal);
    if (!profile && this.autoProvision) {
      profile = await this.provision(principal);
    }
    if (!profile) {
      return { ok: false, reason: "unknown_principal" };
    }
    return { ok: true, profile };
  }

  /**
   * Auto-provision a PAM user's profile row on first successful login.
   * This is the "users table as profile store" model (tynn #271) — the
   * row carries display preferences + dashboard role, but the secret
   * lives with PAM, not here.
   */
  private async provision(principal: string): Promise<AuthUserProfile | null> {
    const now = new Date();
    const profile = {
      id: nanoid(),
      authBackend: "pam" as const,
      principal,
      email: null,
      username: principal,
      passwordHash: null, // never set — PAM owns the secret
      displayName: principal,
      entityId: null,
      dashboardRole: "viewer" as const,
      createdAt: now,
      updatedAt: now,
    };
    try {
      await this.db.insert(users).values(profile);
    } catch {
      // Someone else provisioned between our lookup and now — re-read.
      return this.registry.findProfile("pam", principal);
    }
    return this.registry.findProfile("pam", principal);
  }
}

/**
 * Invoke the PAM helper script. Returns true if the password matched.
 * The helper reads the password from stdin (not argv) so it never shows
 * up in `ps`. Exit code 0 = authenticated, non-zero = rejected.
 */
async function runPamHelper(
  helperPath: string,
  principal: string,
  password: string,
): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn(helperPath, [principal], {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 5_000,
    });
    let resolved = false;
    child.on("exit", (code) => {
      if (!resolved) {
        resolved = true;
        resolve(code === 0);
      }
    });
    child.on("error", () => {
      if (!resolved) {
        resolved = true;
        resolve(false);
      }
    });
    child.stdin.write(password);
    child.stdin.end();
  });
}
