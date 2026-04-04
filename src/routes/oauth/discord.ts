/**
 * Discord OAuth Provider — Discord account and bot linking.
 *
 * Uses the provider factory for the common OAuth flow.
 * Discord-specific: bot scope option, guilds access.
 */

import type { DrizzleDb } from "../../db/client.js";
import { createOAuthRoutes, type OAuthProviderDef } from "./provider-factory.js";

interface DiscordTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

interface DiscordUser {
  id: string;
  username: string;
  discriminator: string;
  email?: string;
}

export const discordProviderDef: OAuthProviderDef = {
  id: "discord",
  label: "Discord",
  authUrl: "https://discord.com/api/oauth2/authorize",
  tokenUrl: "https://discord.com/api/oauth2/token",
  defaultScopes: ["identify", "guilds"],
  parseTokenResponse: (data: unknown) => {
    const res = data as DiscordTokenResponse;
    if (!res.access_token) return null;
    return {
      accessToken: res.access_token,
      refreshToken: res.refresh_token ?? null,
      expiresIn: res.expires_in ?? null,
      scope: res.scope ?? "",
    };
  },
  fetchUserInfo: async (accessToken: string) => {
    const res = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const user = (await res.json()) as DiscordUser;
    return { accountLabel: user.username ?? user.email ?? null };
  },
};

export function discordOAuthRoutes(db: DrizzleDb) {
  return createOAuthRoutes(discordProviderDef, db);
}
