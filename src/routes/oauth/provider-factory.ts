/**
 * OAuth Provider Factory — generic OAuth 2.0 flow generator.
 *
 * Extracts the common pattern from google.ts and github.ts into a reusable
 * factory. Each provider defines its URLs, scopes, and token/userinfo parsing;
 * the factory handles state signing, token exchange, and connection upsert.
 */

import { Hono } from "hono";
import { nanoid } from "nanoid";
import type { AuthEnv } from "../../auth/middleware.js";
import { encrypt, decrypt } from "../../crypto.js";
import { signOAuthState, verifyOAuthState } from "../../security/oauth-state.js";
import type { DrizzleDb } from "../../db/client.js";
import { connections, providerSettings } from "../../db/schema.js";
import { and, eq } from "drizzle-orm";
import { getConfig } from "../../config.js";

// ---------------------------------------------------------------------------
// Provider definition interface
// ---------------------------------------------------------------------------

export interface OAuthProviderDef {
  /** Provider ID stored in the database (e.g. "google", "github", "discord") */
  id: string;
  /** Display label for redirect URLs (e.g. "Google", "GitHub", "Discord") */
  label: string;
  /** OAuth authorization endpoint */
  authUrl: string;
  /** OAuth token exchange endpoint */
  tokenUrl: string;
  /** Default scopes to request */
  defaultScopes: string[];
  /** Extra query params for the auth URL (e.g. access_type=offline) */
  authParams?: Record<string, string>;
  /** Extra headers for the token exchange request */
  tokenHeaders?: Record<string, string>;
  /**
   * Parse the raw token response into a normalized shape.
   * Return null if the response indicates an error.
   */
  parseTokenResponse: (data: unknown) => {
    accessToken: string;
    refreshToken: string | null;
    expiresIn: number | null;
    scope: string;
  } | null;
  /**
   * Fetch user info to get an account label (email, username, etc).
   * Return null if not applicable.
   */
  fetchUserInfo?: (accessToken: string) => Promise<{
    accountLabel: string | null;
  }>;
}

// ---------------------------------------------------------------------------
// Credential resolution (DB first, .env fallback)
// ---------------------------------------------------------------------------

/**
 * Resolve OAuth credentials for a provider.
 * Checks the provider_settings table first (DB-configured);
 * falls back to environment variable config if not found in DB.
 * Returns null if no credentials are available from either source.
 */
async function resolveProviderCreds(
  providerId: string,
  db: DrizzleDb,
): Promise<{ clientId: string; clientSecret: string } | null> {
  // DB lookup
  const rows = await db
    .select()
    .from(providerSettings)
    .where(eq(providerSettings.id, providerId))
    .limit(1);

  const row = rows[0];
  if (row?.clientId && row.clientSecret && row.enabled) {
    try {
      return {
        clientId: decrypt(row.clientId),
        clientSecret: decrypt(row.clientSecret),
      };
    } catch {
      // Corrupted DB entry — fall through to env fallback
    }
  }

  // .env fallback
  const config = getConfig();
  const envCreds = config.providers[providerId as keyof typeof config.providers];
  return envCreds ?? null;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Hono sub-app with /start and /callback routes for the given
 * OAuth provider definition.
 */
export function createOAuthRoutes(provider: OAuthProviderDef, db: DrizzleDb): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();
  const baseUrl = () => getConfig().baseUrl;
  const callbackPath = `/oauth/${provider.id}/callback`;

  // -----------------------------------------------------------------------
  // GET /start — redirect to provider's auth URL
  // -----------------------------------------------------------------------

  app.get("/start", async (c) => {
    const user = c.get("user");
    if (!user) {
      return c.redirect(`/auth/login?redirect=/oauth/${provider.id}/start`);
    }

    const role = c.req.query("role") ?? "owner";
    if (role !== "owner" && role !== "agent") {
      return c.json({ error: "role must be 'owner' or 'agent'" }, 400);
    }

    const providerCreds = await resolveProviderCreds(provider.id, db);
    if (!providerCreds) {
      return c.redirect(`/settings/providers?unconfigured=${provider.id}`);
    }

    const state = signOAuthState({
      userId: user.id,
      role,
      ts: Date.now(),
    });

    const params = new URLSearchParams({
      client_id: providerCreds.clientId,
      redirect_uri: new URL(callbackPath, baseUrl()).toString(),
      response_type: "code",
      scope: provider.defaultScopes.join(" "),
      state,
      ...(provider.authParams ?? {}),
    });

    return c.redirect(`${provider.authUrl}?${params.toString()}`);
  });

  // -----------------------------------------------------------------------
  // GET /callback — exchange code for tokens, upsert connection
  // -----------------------------------------------------------------------

  app.get("/callback", async (c) => {
    const code = c.req.query("code");
    const stateParam = c.req.query("state");
    const error = c.req.query("error");

    if (error || !code || !stateParam) {
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    const parsedState = verifyOAuthState<{ userId: string; role: string; ts: number }>(stateParam);
    if (!parsedState) {
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    // Reject states older than 15 minutes
    if (Date.now() - parsedState.ts > 15 * 60 * 1000) {
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    const providerCreds = await resolveProviderCreds(provider.id, db);
    if (!providerCreds) {
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    // Exchange code for tokens
    const tokenRes = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(provider.tokenHeaders ?? {}),
      },
      body: new URLSearchParams({
        code,
        client_id: providerCreds.clientId,
        client_secret: providerCreds.clientSecret,
        redirect_uri: new URL(callbackPath, baseUrl()).toString(),
        grant_type: "authorization_code",
      }),
    });

    if (!tokenRes.ok && !provider.tokenHeaders) {
      // Some providers return non-200 even on success if Accept header is needed
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    const rawTokens = await tokenRes.json();
    const tokens = provider.parseTokenResponse(rawTokens);

    if (!tokens) {
      return c.redirect(`/connect-result?status=error&provider=${provider.label}`);
    }

    // Fetch user info for account label
    let accountLabel: string | null = null;
    if (provider.fetchUserInfo) {
      try {
        const info = await provider.fetchUserInfo(tokens.accessToken);
        accountLabel = info.accountLabel;
      } catch {
        // Non-fatal — proceed without label
      }
    }

    const tokenExpiresAt = tokens.expiresIn
      ? new Date(Date.now() + tokens.expiresIn * 1000)
      : null;

    // Upsert connection
    const existing = await db
      .select()
      .from(connections)
      .where(
        and(
          eq(connections.userId, parsedState.userId),
          eq(connections.provider, provider.id),
          eq(connections.role, parsedState.role),
        ),
      )
      .limit(1);

    if (existing.length > 0) {
      await db
        .update(connections)
        .set({
          accountLabel,
          accessToken: encrypt(tokens.accessToken),
          refreshToken: tokens.refreshToken
            ? encrypt(tokens.refreshToken)
            : existing[0]!.refreshToken,
          tokenExpiresAt,
          scopes: tokens.scope,
          updatedAt: new Date(),
        })
        .where(eq(connections.id, existing[0]!.id));
    } else {
      await db.insert(connections).values({
        id: nanoid(),
        userId: parsedState.userId,
        provider: provider.id,
        role: parsedState.role,
        accountLabel,
        accessToken: encrypt(tokens.accessToken),
        refreshToken: tokens.refreshToken ? encrypt(tokens.refreshToken) : null,
        tokenExpiresAt,
        scopes: tokens.scope,
      });
    }

    return c.redirect(`/connect-result?status=success&provider=${provider.label}`);
  });

  return app;
}
