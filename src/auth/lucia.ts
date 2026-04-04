import { DrizzlePostgreSQLAdapter } from "@lucia-auth/adapter-drizzle";
import { Lucia } from "lucia";
import type { DrizzleDb } from "../db/client.js";
import { sessions, users } from "../db/schema.js";

export function createLucia(db: DrizzleDb) {
  const adapter = new DrizzlePostgreSQLAdapter(db, sessions, users);

  const lucia = new Lucia(adapter, {
    sessionCookie: {
      attributes: {
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      },
    },
    getUserAttributes(attributes) {
      return {
        email: attributes.email,
        displayName: attributes.displayName,
      };
    },
  });

  return lucia;
}

export type AppLucia = ReturnType<typeof createLucia>;

declare module "lucia" {
  interface Register {
    Lucia: AppLucia;
    DatabaseUserAttributes: {
      email: string;
      displayName: string | null;
    };
  }
}
