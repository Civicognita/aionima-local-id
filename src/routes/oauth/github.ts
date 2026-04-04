/**
 * GitHub OAuth Provider — GitHub account linking.
 *
 * Uses the provider factory for the common OAuth flow.
 * GitHub-specific: no refresh tokens, Accept: application/json for token endpoint.
 */

import type { DrizzleDb } from "../../db/client.js";
import { createOAuthRoutes, type OAuthProviderDef } from "./provider-factory.js";

interface GitHubTokenResponse {
  access_token: string;
  scope: string;
  token_type: string;
  error?: string;
}

interface GitHubUser {
  login: string;
  email: string | null;
}

export const githubProviderDef: OAuthProviderDef = {
  id: "github",
  label: "GitHub",
  authUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  defaultScopes: ["read:user", "user:email"],
  tokenHeaders: {
    Accept: "application/json",
  },
  parseTokenResponse: (data: unknown) => {
    const res = data as GitHubTokenResponse;
    if (res.error || !res.access_token) return null;
    return {
      accessToken: res.access_token,
      refreshToken: null,
      expiresIn: null,
      scope: res.scope ?? "",
    };
  },
  fetchUserInfo: async (accessToken: string) => {
    const res = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    const user = (await res.json()) as GitHubUser;
    return { accountLabel: user.login ?? user.email ?? null };
  },
};

export function githubOAuthRoutes(db: DrizzleDb) {
  return createOAuthRoutes(githubProviderDef, db);
}
