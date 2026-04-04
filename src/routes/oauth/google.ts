/**
 * Google OAuth Provider — Gmail and Google account linking.
 *
 * Uses the provider factory for the common OAuth flow.
 * Google-specific: offline access, refresh tokens, userinfo endpoint.
 */

import type { DrizzleDb } from "../../db/client.js";
import { createOAuthRoutes, type OAuthProviderDef } from "./provider-factory.js";

interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

interface GoogleUserInfo {
  email: string;
}

export const googleProviderDef: OAuthProviderDef = {
  id: "google",
  label: "Google",
  authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: "https://oauth2.googleapis.com/token",
  defaultScopes: [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
  ],
  authParams: {
    access_type: "offline",
    prompt: "consent",
  },
  parseTokenResponse: (data: unknown) => {
    const res = data as GoogleTokenResponse;
    if (!res.access_token) return null;
    return {
      accessToken: res.access_token,
      refreshToken: res.refresh_token ?? null,
      expiresIn: res.expires_in ?? null,
      scope: res.scope ?? "",
    };
  },
  fetchUserInfo: async (accessToken: string) => {
    const res = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const info = (await res.json()) as GoogleUserInfo;
    return { accountLabel: info.email ?? null };
  },
};

export function googleOAuthRoutes(db: DrizzleDb) {
  return createOAuthRoutes(googleProviderDef, db);
}
