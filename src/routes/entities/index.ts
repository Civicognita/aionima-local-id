/**
 * Entity API Routes — REST endpoints for entity management.
 *
 * Endpoints:
 *   POST   /api/entities              — create entity (owner-only)
 *   GET    /api/entities              — list all entities on this node
 *   GET    /api/entities/:id          — get entity by ID
 *   GET    /api/entities/by-geid/:geid     — lookup by GEID
 *   GET    /api/entities/by-alias/:alias   — lookup by COA alias
 *   POST   /api/entities/register-owner    — genesis onboarding: #E0 + $A0
 *   POST   /api/entities/:id/bind-agent    — bind $A to #E or #O
 *   GET    /api/entities/:ownerId/agents   — list bound agents
 */

import { Hono } from "hono";
import type { AuthEnv } from "../../auth/middleware.js";
import type { EntityService } from "../../services/entity-service.js";

export function entityRoutes(entityService: EntityService) {
  const app = new Hono<AuthEnv>();

  // -----------------------------------------------------------------------
  // POST /register-owner — genesis onboarding, creates #E0 + $A0
  // Called by AGI during owner-profile onboarding step.
  // -----------------------------------------------------------------------

  app.post("/register-owner", async (c) => {
    let body: { displayName?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.displayName?.trim()) {
      return c.json({ error: "displayName is required" }, 400);
    }

    // Check if genesis owner already exists
    const exists = await entityService.hasGenesisOwner();
    if (exists) {
      return c.json({ error: "Genesis owner (#E0) already exists" }, 409);
    }

    try {
      const result = await entityService.createOwnerEntity(body.displayName.trim());

      return c.json({
        owner: {
          id: result.owner.id,
          type: result.owner.type,
          displayName: result.owner.displayName,
          coaAlias: result.owner.coaAlias,
          scope: result.owner.scope,
          geid: result.ownerGeid.geid,
        },
        agent: {
          id: result.agent.id,
          type: result.agent.type,
          displayName: result.agent.displayName,
          coaAlias: result.agent.coaAlias,
          scope: result.agent.scope,
          geid: result.agentGeid.geid,
        },
        registrationId: result.registrationId,
      });
    } catch (e) {
      return c.json({ error: `Failed to create owner: ${String(e)}` }, 500);
    }
  });

  // -----------------------------------------------------------------------
  // POST / — create entity (requires auth)
  // -----------------------------------------------------------------------

  app.post("/", async (c) => {
    const user = c.get("user");
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    let body: {
      type?: string;
      displayName?: string;
      scope?: "local" | "registered";
      parentEntityId?: string;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    const { type, displayName, scope, parentEntityId } = body;

    if (!type || !["E", "O", "T", "F", "A"].includes(type)) {
      return c.json({ error: "type must be one of: E, O, T, F, A" }, 400);
    }
    if (!displayName?.trim()) {
      return c.json({ error: "displayName is required" }, 400);
    }

    const entityScope = scope ?? "local";
    if (entityScope !== "local" && entityScope !== "registered") {
      return c.json({ error: "scope must be 'local' or 'registered'" }, 400);
    }

    try {
      const result = await entityService.createEntity(
        type,
        displayName.trim(),
        entityScope,
        parentEntityId,
      );

      const geid = result.geid;
      return c.json({
        id: result.entity.id,
        type: result.entity.type,
        displayName: result.entity.displayName,
        coaAlias: result.entity.coaAlias,
        scope: result.entity.scope,
        geid: geid.geid,
        createdAt: result.entity.createdAt,
      });
    } catch (e) {
      return c.json({ error: `Failed to create entity: ${String(e)}` }, 500);
    }
  });

  // -----------------------------------------------------------------------
  // GET / — list all entities
  // -----------------------------------------------------------------------

  app.get("/", async (c) => {
    const all = await entityService.listEntities();
    return c.json({ entities: all });
  });

  // -----------------------------------------------------------------------
  // GET /by-geid/:geid — lookup by GEID
  // (Must be before /:id to avoid route conflict)
  // -----------------------------------------------------------------------

  app.get("/by-geid/:geid", async (c) => {
    const geid = c.req.param("geid");
    const entity = await entityService.getByGeid(geid);
    if (!entity) {
      return c.json({ error: "Entity not found" }, 404);
    }

    const geidRecord = await entityService.getEntityGeid(entity.id);
    return c.json({ ...entity, geid: geidRecord?.geid });
  });

  // -----------------------------------------------------------------------
  // GET /by-alias/:alias — lookup by COA alias
  // -----------------------------------------------------------------------

  app.get("/by-alias/:alias", async (c) => {
    const alias = decodeURIComponent(c.req.param("alias"));
    const entity = await entityService.getByAlias(alias);
    if (!entity) {
      return c.json({ error: "Entity not found" }, 404);
    }

    const geidRecord = await entityService.getEntityGeid(entity.id);
    return c.json({ ...entity, geid: geidRecord?.geid });
  });

  // -----------------------------------------------------------------------
  // GET /:id/agents — list agents bound to an owner
  // (Must be before /:id to avoid route conflict)
  // -----------------------------------------------------------------------

  app.get("/:ownerId/agents", async (c) => {
    const ownerId = c.req.param("ownerId");
    const agents = await entityService.getOwnerAgents(ownerId);
    return c.json({ agents });
  });

  // -----------------------------------------------------------------------
  // POST /:id/bind-agent — bind $A to #E or #O
  // -----------------------------------------------------------------------

  app.post("/:id/bind-agent", async (c) => {
    const user = c.get("user");
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const ownerId = c.req.param("id");
    let body: { agentEntityId?: string; bindingType?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.agentEntityId) {
      return c.json({ error: "agentEntityId is required" }, 400);
    }

    try {
      await entityService.bindAgent(ownerId, body.agentEntityId, body.bindingType);
      return c.json({ ok: true });
    } catch (e) {
      return c.json({ error: String(e) }, 400);
    }
  });

  // -----------------------------------------------------------------------
  // GET /:id — get entity by ID
  // -----------------------------------------------------------------------

  app.get("/:id", async (c) => {
    const id = c.req.param("id");
    const entity = await entityService.getEntity(id);
    if (!entity) {
      return c.json({ error: "Entity not found" }, 404);
    }

    const geidRecord = await entityService.getEntityGeid(entity.id);
    return c.json({ ...entity, geid: geidRecord?.geid });
  });

  return app;
}
