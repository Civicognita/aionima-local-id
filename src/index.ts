import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { sessionMiddleware } from "./auth/middleware.js";
import { networkIdentityMiddleware, setPeerKeyResolver } from "./auth/network-identity.js";
import { createLucia } from "./auth/lucia.js";
import { db } from "./db/client.js";
import { authRoutes } from "./routes/auth.js";
import { entityRoutes } from "./routes/entities/index.js";
import { connectRoutes } from "./routes/connect.js";
import { createEntityService } from "./services/entity-service.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { handoffRoutes } from "./routes/handoff.js";
import { channelRoutes } from "./routes/channels.js";
import { settingsRoutes } from "./routes/settings.js";
import { userRoutes } from "./routes/users.js";
import { oauthDelegateRoutes } from "./routes/oauth-delegate.js";
import { federationIdentityRoutes, buildNodeManifest } from "./routes/federation/identity.js";
import { csrfMiddleware } from "./security/csrf.js";
import { rateLimit } from "./security/rate-limit.js";
import { startHandoffCleanup } from "./jobs/cleanup.js";
import { loadConfig } from "./config.js";
import { registerProvider, mountProviders } from "./providers/registry.js";
import { googleProviderDef } from "./routes/oauth/google.js";
import { githubProviderDef } from "./routes/oauth/github.js";
import { discordProviderDef } from "./routes/oauth/discord.js";
import type { AuthEnv } from "./auth/middleware.js";
import { readView } from "./views/loader.js";

// Load and validate config before anything else
const config = loadConfig();

const lucia = createLucia(db);
const entityService = createEntityService(db);

// Set up peer key resolver for federation auth.
// Local-ID only knows local peers — return null for all external nodes.
setPeerKeyResolver((_nodeId: string): string | null => null);

const app = new Hono<AuthEnv>();

// ---------------------------------------------------------------------------
// Global middleware (order matters)
// ---------------------------------------------------------------------------

// 1. Security headers — allow framing from the AGI dashboard (*.ai.on)
app.use("/*", secureHeaders({
  xFrameOptions: false,
  contentSecurityPolicy: {
    frameAncestors: ["'self'", "https://*.ai.on", "https://ai.on"],
  },
}));

// 2. Session middleware — cookie-based sessions, populates c.var.user
app.use("/*", sessionMiddleware(lucia));

// 3. Network identity — private network auto-IDENT, API key, Mycelium-Sig
//    Runs AFTER session middleware so it can check if Lucia already identified the user.
app.use("/*", networkIdentityMiddleware());

// ---------------------------------------------------------------------------
// CORS — scoped per route group
// ---------------------------------------------------------------------------

// Handoff poll/create: open CORS (gateways on any origin)
app.use(
  "/api/handoff/*/poll",
  cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], allowHeaders: ["Content-Type"], maxAge: 3600 }),
);
app.use(
  "/api/handoff/create",
  cors({ origin: "*", allowMethods: ["POST", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"], maxAge: 3600 }),
);

// Provider registry + federation: open CORS
app.use("/api/providers", cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], allowHeaders: ["Content-Type"], maxAge: 3600 }));
app.use("/federation/*", cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["Content-Type", "Mycelium-Sig"], maxAge: 3600 }));
app.use("/.well-known/*", cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], maxAge: 3600 }));

// Entity API: open CORS (AGI gateway calls these endpoints)
app.use("/api/entities/*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
  maxAge: 3600,
}));

// User API: open CORS (AGI gateway proxies admin user CRUD)
app.use("/api/users/*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
  maxAge: 3600,
}));

// ---------------------------------------------------------------------------
// CSRF — protects browser state-changing endpoints
// Handoff create/poll and federation endpoints are exempt (API-to-API, no cookies)
// ---------------------------------------------------------------------------

app.use("/auth/*", csrfMiddleware());
app.use("/api/connections/*", csrfMiddleware());
app.use("/api/handoff/*/approve", csrfMiddleware());
app.use("/api/channels/test", csrfMiddleware());
app.use("/api/channels/save", csrfMiddleware());
app.use("/api/settings/providers/*", csrfMiddleware());
app.use("/api/oauth/delegate", csrfMiddleware());

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

app.use("/auth/login", rateLimit({ windowMs: 60_000, max: 5, keyPrefix: "login" }));
app.use("/auth/register", rateLimit({ windowMs: 60_000, max: 3, keyPrefix: "register" }));
app.use("/api/handoff/create", rateLimit({ windowMs: 60_000, max: 10, keyPrefix: "handoff" }));

// ---------------------------------------------------------------------------
// Provider registration — register all known providers, mount only configured ones
// ---------------------------------------------------------------------------

registerProvider(googleProviderDef);
registerProvider(githubProviderDef);
registerProvider(discordProviderDef);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Auth routes — email/password with entity auto-creation
app.route("/auth", authRoutes(db, lucia, entityService));

// Entity routes — entity management, register-owner, bind-agent
app.route("/api/entities", entityRoutes(entityService));

// Dynamic OAuth provider routes — only mounts providers with configured credentials
const mounted = mountProviders(app, db);
const availableProviders = mounted.filter((p) => p.available).map((p) => p.def.label);
const skippedProviders = mounted.filter((p) => !p.available).map((p) => p.def.label);

app.route("/api/connections", connectRoutes(db));
app.route("/api/handoff", handoffRoutes(db, lucia));
app.route("/api/users", userRoutes(db, entityService));
app.route("/api/oauth/delegate", oauthDelegateRoutes(db));
app.route("/dashboard", dashboardRoutes(db));
app.route("/channels", channelRoutes(db));
app.route("/api/channels", channelRoutes(db));
app.route("/settings", settingsRoutes(db));
app.route("/api/settings", settingsRoutes(db));

// Federation identity routes — available in all modes
app.route("/federation", federationIdentityRoutes());

// Well-known node manifest
app.get("/.well-known/mycelium-node.json", (c) => c.json(buildNodeManifest()));

// Provider discovery endpoint
app.get("/api/providers", (c) => {
  return c.json({
    providers: mounted.map((p) => ({
      id: p.def.id,
      label: p.def.label,
      available: p.available,
    })),
  });
});

// Login page (standalone — central mode primarily)
app.get("/auth/login", async (c) => {
  const loginHtml = await readView("login.html");
  const content = loginHtml.replace("{{handoff_id}}", "");
  const layout = await readView("layout.html");
  const html = layout
    .replace("{{title}}", "Aionima ID — Login")
    .replace("{{content}}", content);
  return c.html(html);
});

// Connect result page
app.get("/connect-result", async (c) => {
  const resultHtml = await readView("connect-result.html");
  const layout = await readView("layout.html");
  const html = layout
    .replace("{{title}}", "Aionima ID — Connect Result")
    .replace("{{content}}", resultHtml);
  return c.html(html);
});

// Root redirect
app.get("/", (c) => c.redirect("/dashboard"));

// Health check
app.get("/health", (c) =>
  c.json({ status: "ok", service: "aionima-local-id", mode: "local" }),
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const port = config.port;

// Start periodic cleanup of expired handoffs
startHandoffCleanup(db);

if (availableProviders.length > 0) {
  console.log(`OAuth providers: ${availableProviders.join(", ")}`);
}
if (skippedProviders.length > 0) {
  console.log(`Skipped (no credentials): ${skippedProviders.join(", ")}`);
}

const authModes = ["private-network"];
if (config.ownerNode.apiKey) authModes.push("node-api-key");
authModes.push("mycelium-sig", "session");

console.log(`Auth modes: ${authModes.join(", ")}`);
console.log(`Aionima Local-ID Service starting on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
