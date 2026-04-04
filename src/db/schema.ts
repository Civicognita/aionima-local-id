import { pgTable, text, timestamp, unique, boolean as pgBoolean } from "drizzle-orm/pg-core";

// ---------------------------------------------------------------------------
// Auth tables
// ---------------------------------------------------------------------------

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  email: text("email").unique(),
  username: text("username").unique(),
  passwordHash: text("password_hash").notNull(),
  displayName: text("display_name"),
  entityId: text("entity_id").references((): any => entities.id),
  /** Dashboard role: admin, operator, or viewer. Genesis owner defaults to admin. */
  dashboardRole: text("dashboard_role").notNull().default("viewer"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// ---------------------------------------------------------------------------
// Entity Classification tables (Phase 1)
// ---------------------------------------------------------------------------

/** Unified entity table — sentient (#E, #O, #T, #F) and resource ($A) entities. */
export const entities = pgTable("entities", {
  id: text("id").primaryKey(),
  /** Entity type letter: E=individual, O=org, T=team, F=family, A=agent/app */
  type: text("type").notNull(),
  displayName: text("display_name").notNull(),
  /** Full COA alias including prefix: #E0, ~E1, $A0, #E0~E1 */
  coaAlias: text("coa_alias").notNull().unique(),
  /** 'local' = ~prefix (not HIVE-registered), 'registered' = #/$ prefix (HIVE-registered or genesis) */
  scope: text("scope").notNull().default("local"),
  /** The registered entity this local entity belongs to (null for top-level registered entities) */
  parentEntityId: text("parent_entity_id").references((): any => entities.id),
  /** Verification tier: unverified → verified → sealed */
  verificationTier: text("verification_tier").notNull().default("unverified"),
  /** Links to auth user (nullable — $A entities don't have auth users) */
  userId: text("user_id").references((): any => users.id),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

/** Local GEID keypair storage — Ed25519 keys for entity identity. */
export const geidLocal = pgTable("geid_local", {
  entityId: text("entity_id")
    .primaryKey()
    .references(() => entities.id),
  /** GEID in standard format: geid:<base58-ed25519-pubkey> */
  geid: text("geid").notNull().unique(),
  /** PEM-encoded SPKI public key */
  publicKeyPem: text("public_key_pem").notNull(),
  /** PEM-encoded PKCS8 private key — encrypted with AES-256-GCM (config.encryptionKey) */
  privateKeyPem: text("private_key_pem"),
  /** Whether this entity opts into cross-node discovery */
  discoverable: pgBoolean("discoverable").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

/** Agent bindings — links $A agent entities to their owner (#E or #O). */
export const agentBindings = pgTable(
  "agent_bindings",
  {
    id: text("id").primaryKey(),
    /** Owner entity (#E or #O) */
    ownerId: text("owner_id")
      .notNull()
      .references(() => entities.id),
    /** Agent entity ($A) */
    agentId: text("agent_id")
      .notNull()
      .references(() => entities.id),
    /** Binding type: 'primary' = main agent, 'secondary' = additional */
    bindingType: text("binding_type").notNull().default("primary"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (t) => [unique("agent_bindings_owner_agent").on(t.ownerId, t.agentId)],
);

/** On-chain-ready registration records — audit trail for entity creation. */
export const registrations = pgTable("registrations", {
  id: text("id").primaryKey(),
  entityId: text("entity_id")
    .notNull()
    .references(() => entities.id),
  /** Registration type: owner, user, agent, org */
  registrationType: text("registration_type").notNull(),
  /** Who referred this entity (null for genesis) */
  referrerEntityId: text("referrer_entity_id").references(() => entities.id),
  /** Referral source: 'direct', 'station:xyz', 'channel:telegram' */
  referralSource: text("referral_source"),
  /** Referral result: 'instant' or 'delayed' */
  referralResult: text("referral_result").notNull(),
  /** $A entity used during registration (if any) */
  agentEntityId: text("agent_entity_id").references(() => entities.id),
  /** SHA-256 hash of canonical registration JSON */
  recordHash: text("record_hash").notNull(),
  /** Ed25519 signature by entity's GEID key */
  recordSignature: text("record_signature"),
  /** Blockchain transaction ID — null until on-chain (future HIVE-ID) */
  chainTxId: text("chain_tx_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id),
  expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
    .notNull(),
});

export const connections = pgTable(
  "connections",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    provider: text("provider").notNull(),
    role: text("role").notNull(),
    accountLabel: text("account_label"),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    tokenExpiresAt: timestamp("token_expires_at"),
    scopes: text("scopes"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (t) => [unique("connections_user_provider_role").on(t.userId, t.provider, t.role)],
);

export const handoffs = pgTable("handoffs", {
  id: text("id").primaryKey(),
  userId: text("user_id").references(() => users.id),
  status: text("status").notNull().default("pending"),
  connectedServices: text("connected_services"),
  /** Handoff purpose — controls which providers are shown/included.
   *  "onboarding" = all providers, "channel:discord" = discord only, etc. */
  purpose: text("purpose").default("onboarding"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  expiresAt: timestamp("expires_at").notNull(),
});

// ---------------------------------------------------------------------------
// Provider Settings (DB-backed OAuth credentials)
// ---------------------------------------------------------------------------

/** Per-provider OAuth credentials, encrypted at rest. */
export const providerSettings = pgTable("provider_settings", {
  id: text("id").primaryKey(),
  clientId: text("client_id"),
  clientSecret: text("client_secret"),
  enabled: pgBoolean("enabled").default(false).notNull(),
  configuredAt: timestamp("configured_at"),
  updatedAt: timestamp("updated_at"),
});

// ---------------------------------------------------------------------------
// Type exports
// ---------------------------------------------------------------------------

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type Connection = typeof connections.$inferSelect;
export type NewConnection = typeof connections.$inferInsert;
export type Handoff = typeof handoffs.$inferSelect;
export type NewHandoff = typeof handoffs.$inferInsert;
export type EntityRecord = typeof entities.$inferSelect;
export type NewEntity = typeof entities.$inferInsert;
export type GeidLocalRecord = typeof geidLocal.$inferSelect;
export type AgentBinding = typeof agentBindings.$inferSelect;
export type Registration = typeof registrations.$inferSelect;
export type ProviderSetting = typeof providerSettings.$inferSelect;
export type NewProviderSetting = typeof providerSettings.$inferInsert;
