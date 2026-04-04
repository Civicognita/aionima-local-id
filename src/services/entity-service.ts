/**
 * Entity Service — entity CRUD, GEID generation, COA alias management,
 * agent binding, and on-chain-ready registration records.
 *
 * GEID generation is ported from agi/packages/entity-model/src/geid.ts
 * to keep Local-ID self-contained (no cross-repo runtime dependency).
 */

import {
  createPrivateKey,
  generateKeyPairSync,
  createHash,
  sign,
} from "node:crypto";
import { nanoid } from "nanoid";
import { eq, and, like, sql } from "drizzle-orm";
import type { DrizzleDb } from "../db/client.js";
import {
  entities,
  geidLocal,
  agentBindings,
  registrations,
  users,
} from "../db/schema.js";
import type { EntityRecord, GeidLocalRecord } from "../db/schema.js";
import { encrypt } from "../crypto.js";

// ---------------------------------------------------------------------------
// Base58 encoding (Bitcoin-style, matches AGI entity-model)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(buffer: Uint8Array): string {
  const digits = [0];
  for (const byte of buffer) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let output = "";
  for (const byte of buffer) {
    if (byte !== 0) break;
    output += BASE58_ALPHABET[0];
  }

  for (let i = digits.length - 1; i >= 0; i--) {
    output += BASE58_ALPHABET[digits[i] as number];
  }

  return output;
}

// ---------------------------------------------------------------------------
// GEID generation (matches agi/packages/entity-model/src/geid.ts)
// ---------------------------------------------------------------------------

const GEID_PREFIX = "geid:";

interface EntityKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
  geid: string;
  publicKeyBase58: string;
}

function generateEntityKeypair(): EntityKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");

  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;

  // Extract raw 32-byte public key from SPKI DER (12-byte header + 32-byte key)
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(12);
  const publicKeyBase58 = encodeBase58(rawPublicKey);

  const geid = `${GEID_PREFIX}${publicKeyBase58}`;

  return { privateKeyPem, publicKeyPem, geid, publicKeyBase58 };
}

// ---------------------------------------------------------------------------
// COA alias helpers
// ---------------------------------------------------------------------------

/** Entity types in the sentient domain (#) */
const SENTIENT_TYPES = new Set(["E", "O", "T", "F"]);

/** Get the COA prefix for an entity type + scope */
function aliasPrefix(type: string, scope: string): string {
  if (scope === "local") return "~";
  // Registered: sentient types get #, resource types get $
  return SENTIENT_TYPES.has(type) ? "#" : "$";
}

// ---------------------------------------------------------------------------
// Registration record helpers
// ---------------------------------------------------------------------------

interface RegistrationPayload {
  version: number;
  type: "entity-registration";
  entity: {
    geid: string;
    classification: string;
    coaAlias: string;
    scope: string;
    displayName: string;
  };
  registration: {
    type: string;
    agentBinding?: { geid: string; alias: string } | null;
    referrer: string | null;
    source: string;
    result: string;
  };
  timestamp: string;
}

function buildRecordHash(payload: RegistrationPayload): string {
  const canonical = JSON.stringify(payload);
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function signRecord(payload: RegistrationPayload, privateKeyPem: string): string {
  const canonical = JSON.stringify(payload);
  const privateKey = createPrivateKey(privateKeyPem);
  return `ed25519:${sign(null, Buffer.from(canonical), privateKey).toString("hex")}`;
}

// ---------------------------------------------------------------------------
// Entity Service
// ---------------------------------------------------------------------------

export interface CreateEntityResult {
  entity: EntityRecord;
  geid: GeidLocalRecord;
}

export interface RegisterOwnerResult {
  owner: EntityRecord;
  ownerGeid: GeidLocalRecord;
  agent: EntityRecord;
  agentGeid: GeidLocalRecord;
  registrationId: string;
}

export function createEntityService(db: DrizzleDb) {
  // -----------------------------------------------------------------------
  // nextAlias — compute the next sequential COA alias for a type/scope/parent
  // -----------------------------------------------------------------------

  async function nextAlias(
    type: string,
    scope: "local" | "registered",
    parentAlias?: string,
  ): Promise<string> {
    const prefix = aliasPrefix(type, scope);

    // Count existing entities of this type + scope to find the next index
    // For local entities, scope within the parent
    let pattern: string;
    if (scope === "local" && parentAlias) {
      // Local entities under a parent: full alias = parentAlias~{prefix}{type}{n}
      // We look for aliases starting with parentAlias~ and containing the type
      pattern = `${parentAlias}~${type}%`;
    } else {
      // Top-level: #E0, #E1, $A0, etc.
      pattern = `${prefix}${type}%`;
    }

    const result = await db
      .select({ count: sql<number>`count(*)` })
      .from(entities)
      .where(like(entities.coaAlias, pattern));

    const count = Number(result[0]?.count ?? 0);

    // For local entities under a parent, start at 1 (parent is implicitly "0")
    const index = scope === "local" ? count + 1 : count;

    if (scope === "local" && parentAlias) {
      return `${parentAlias}~${type}${index}`;
    }
    return `${prefix}${type}${index}`;
  }

  // -----------------------------------------------------------------------
  // createEntity — base entity creation with GEID keypair
  // -----------------------------------------------------------------------

  async function createEntity(
    type: string,
    displayName: string,
    scope: "local" | "registered",
    parentEntityId?: string,
    userId?: string,
  ): Promise<CreateEntityResult> {
    const id = nanoid();
    const keypair = generateEntityKeypair();

    // Resolve parent alias for local entities
    let parentAlias: string | undefined;
    if (scope === "local" && parentEntityId) {
      const [parent] = await db
        .select()
        .from(entities)
        .where(eq(entities.id, parentEntityId))
        .limit(1);
      parentAlias = parent?.coaAlias;
    }

    const coaAlias = await nextAlias(type, scope, parentAlias);

    const now = new Date();
    await db.insert(entities).values({
      id,
      type,
      displayName,
      coaAlias,
      scope,
      parentEntityId: parentEntityId ?? null,
      verificationTier: "unverified",
      userId: userId ?? null,
      createdAt: now,
      updatedAt: now,
    });

    // Encrypt private key before storing
    const encryptedPrivateKey = encrypt(keypair.privateKeyPem);

    await db.insert(geidLocal).values({
      entityId: id,
      geid: keypair.geid,
      publicKeyPem: keypair.publicKeyPem,
      privateKeyPem: encryptedPrivateKey,
      discoverable: false,
      createdAt: now,
    });

    const [entity] = await db
      .select()
      .from(entities)
      .where(eq(entities.id, id))
      .limit(1);

    const [geid] = await db
      .select()
      .from(geidLocal)
      .where(eq(geidLocal.entityId, id))
      .limit(1);

    return { entity: entity!, geid: geid! };
  }

  // -----------------------------------------------------------------------
  // createOwnerEntity — genesis: #E0 + $A0 + binding + registration
  // -----------------------------------------------------------------------

  async function createOwnerEntity(displayName: string): Promise<RegisterOwnerResult> {
    // Create #E0 — genesis owner (scope=registered, the node authority)
    const owner = await createEntity("E", displayName, "registered");

    // Create $A0 — primary agent bound to the owner
    const agent = await createEntity("A", "Aionima", "registered");

    // Bind agent to owner
    await db.insert(agentBindings).values({
      id: nanoid(),
      ownerId: owner.entity.id,
      agentId: agent.entity.id,
      bindingType: "primary",
      createdAt: new Date(),
    });

    // Build registration record
    const timestamp = new Date().toISOString();
    const payload: RegistrationPayload = {
      version: 1,
      type: "entity-registration",
      entity: {
        geid: owner.geid.geid,
        classification: "#E",
        coaAlias: owner.entity.coaAlias,
        scope: "registered",
        displayName,
      },
      registration: {
        type: "owner",
        agentBinding: { geid: agent.geid.geid, alias: agent.entity.coaAlias },
        referrer: null,
        source: "direct",
        result: "instant",
      },
      timestamp,
    };

    const recordHash = buildRecordHash(payload);

    // Sign with owner's private key (decrypt first)
    const { decrypt } = await import("../crypto.js");
    const ownerPrivateKey = decrypt(owner.geid.privateKeyPem!);
    const recordSignature = signRecord(payload, ownerPrivateKey);

    const regId = nanoid();
    await db.insert(registrations).values({
      id: regId,
      entityId: owner.entity.id,
      registrationType: "owner",
      referrerEntityId: null,
      referralSource: "direct",
      referralResult: "instant",
      agentEntityId: agent.entity.id,
      recordHash,
      recordSignature,
      chainTxId: null,
      createdAt: new Date(),
    });

    return {
      owner: owner.entity,
      ownerGeid: owner.geid,
      agent: agent.entity,
      agentGeid: agent.geid,
      registrationId: regId,
    };
  }

  // -----------------------------------------------------------------------
  // createLocalUser — ~E{n} under a parent entity
  // -----------------------------------------------------------------------

  async function createLocalUser(
    displayName: string,
    parentEntityId: string,
    userId?: string,
  ): Promise<CreateEntityResult> {
    return createEntity("E", displayName, "local", parentEntityId, userId);
  }

  // -----------------------------------------------------------------------
  // Lookup functions
  // -----------------------------------------------------------------------

  async function getEntity(id: string): Promise<EntityRecord | null> {
    const [entity] = await db
      .select()
      .from(entities)
      .where(eq(entities.id, id))
      .limit(1);
    return entity ?? null;
  }

  async function getByGeid(geid: string): Promise<EntityRecord | null> {
    const [mapping] = await db
      .select()
      .from(geidLocal)
      .where(eq(geidLocal.geid, geid))
      .limit(1);
    if (!mapping) return null;
    return getEntity(mapping.entityId);
  }

  async function getByAlias(alias: string): Promise<EntityRecord | null> {
    const [entity] = await db
      .select()
      .from(entities)
      .where(eq(entities.coaAlias, alias))
      .limit(1);
    return entity ?? null;
  }

  async function getEntityGeid(entityId: string): Promise<GeidLocalRecord | null> {
    const [geid] = await db
      .select()
      .from(geidLocal)
      .where(eq(geidLocal.entityId, entityId))
      .limit(1);
    return geid ?? null;
  }

  async function listEntities(): Promise<EntityRecord[]> {
    return db.select().from(entities);
  }

  // -----------------------------------------------------------------------
  // bindAgent — link a $A to an owner (#E or #O)
  // -----------------------------------------------------------------------

  async function bindAgent(
    ownerEntityId: string,
    agentEntityId: string,
    bindingType: string = "primary",
  ): Promise<void> {
    const owner = await getEntity(ownerEntityId);
    if (!owner || !SENTIENT_TYPES.has(owner.type)) {
      throw new Error("Owner must be a sentient entity (#E, #O, #T, or #F)");
    }

    const agent = await getEntity(agentEntityId);
    if (!agent || agent.type !== "A") {
      throw new Error("Agent must be a $A entity");
    }

    await db.insert(agentBindings).values({
      id: nanoid(),
      ownerId: ownerEntityId,
      agentId: agentEntityId,
      bindingType,
      createdAt: new Date(),
    });
  }

  // -----------------------------------------------------------------------
  // getOwnerAgents — list agents bound to an owner
  // -----------------------------------------------------------------------

  async function getOwnerAgents(ownerEntityId: string): Promise<EntityRecord[]> {
    const bindings = await db
      .select()
      .from(agentBindings)
      .where(eq(agentBindings.ownerId, ownerEntityId));

    const agentIds = bindings.map((b) => b.agentId);
    if (agentIds.length === 0) return [];

    const agents: EntityRecord[] = [];
    for (const agentId of agentIds) {
      const entity = await getEntity(agentId);
      if (entity) agents.push(entity);
    }
    return agents;
  }

  // -----------------------------------------------------------------------
  // linkUserToEntity — set entityId on a users row
  // -----------------------------------------------------------------------

  async function linkUserToEntity(userId: string, entityId: string): Promise<void> {
    await db
      .update(users)
      .set({ entityId })
      .where(eq(users.id, userId));
  }

  // -----------------------------------------------------------------------
  // hasGenesisOwner — check if #E0 already exists
  // -----------------------------------------------------------------------

  async function hasGenesisOwner(): Promise<boolean> {
    const [owner] = await db
      .select()
      .from(entities)
      .where(and(eq(entities.coaAlias, "#E0"), eq(entities.scope, "registered")))
      .limit(1);
    return owner !== undefined;
  }

  return {
    createEntity,
    createOwnerEntity,
    createLocalUser,
    getEntity,
    getByGeid,
    getByAlias,
    getEntityGeid,
    listEntities,
    bindAgent,
    getOwnerAgents,
    linkUserToEntity,
    hasGenesisOwner,
    nextAlias,
  };
}

export type EntityService = ReturnType<typeof createEntityService>;
