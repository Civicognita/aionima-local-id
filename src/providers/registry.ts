/**
 * Provider Registry — dynamic OAuth provider registration.
 *
 * Instead of hardcoding provider routes in index.ts, providers register
 * dynamically based on which env vars are configured. The handoff approve
 * page can query available providers to show only what's usable.
 */

import type { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { DrizzleDb } from "../db/client.js";
import type { OAuthProviderDef } from "../routes/oauth/provider-factory.js";
import { createOAuthRoutes } from "../routes/oauth/provider-factory.js";
import { getConfig } from "../config.js";
import { providerSettings } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegisteredProvider {
  def: OAuthProviderDef;
  available: boolean;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const providerDefs: OAuthProviderDef[] = [];

/**
 * Register a provider definition. Call before mountProviders().
 */
export function registerProvider(def: OAuthProviderDef): void {
  providerDefs.push(def);
}

/**
 * Mount OAuth routes for all registered providers.
 * All providers are always mounted — credential availability is checked at
 * request time in the factory (DB-configured credentials take precedence
 * over .env-configured ones, with .env as fallback).
 * Returns the list of registered providers with their current availability
 * status based on env config (DB availability is checked at runtime).
 */
export function mountProviders(app: Hono<AuthEnv>, db: DrizzleDb): RegisteredProvider[] {
  const config = getConfig();
  const result: RegisteredProvider[] = [];

  for (const def of providerDefs) {
    // Always mount — factory handles missing credentials gracefully
    const routes = createOAuthRoutes(def, db);
    app.route(`/oauth/${def.id}`, routes);

    // Report env-based availability for startup logging
    const envCreds = config.providers[def.id as keyof typeof config.providers];
    result.push({ def, available: envCreds !== null && envCreds !== undefined });
  }

  return result;
}

/**
 * Get all registered providers with their availability status (env-only, sync).
 */
export function getRegisteredProviders(): RegisteredProvider[] {
  const config = getConfig();
  return providerDefs.map((def) => ({
    def,
    available: config.providers[def.id as keyof typeof config.providers] !== null,
  }));
}

/**
 * Get available provider IDs using both DB settings and .env config.
 * A provider is available if it has credentials in either source.
 */
export async function getAvailableProviderIds(db: DrizzleDb): Promise<string[]> {
  const config = getConfig();

  // Fetch DB-configured providers that are enabled and have credentials
  const dbRows = await db
    .select({ id: providerSettings.id, enabled: providerSettings.enabled, clientId: providerSettings.clientId })
    .from(providerSettings);

  const dbConfigured = new Set(
    dbRows
      .filter((r) => r.enabled && !!r.clientId)
      .map((r) => r.id),
  );

  return providerDefs
    .filter((def) => {
      const inDb = dbConfigured.has(def.id);
      const inEnv = config.providers[def.id as keyof typeof config.providers] !== null;
      return inDb || inEnv;
    })
    .map((def) => def.id);
}

/**
 * Get only the available (configured) providers (env-only, sync — legacy).
 * Prefer getAvailableProviderIds(db) when a DB instance is available.
 */
export function getAvailableProviders(): OAuthProviderDef[] {
  const config = getConfig();
  return providerDefs.filter(
    (def) => config.providers[def.id as keyof typeof config.providers] !== null,
  );
}
