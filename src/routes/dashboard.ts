import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections } from "../db/schema.js";
import { escapeHtml } from "../security/escape.js";
import { readView } from "../views/loader.js";
import { getAvailableProviderIds } from "../providers/registry.js";

export function dashboardRoutes(db: DrizzleDb) {
  const app = new Hono<AuthEnv & { Variables: { identity?: NetworkIdentity } }>();

  app.get("/", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.redirect("/auth/login");
    }

    // In local mode without session, show all connections (owner has full access)
    const userConnections = user
      ? await db.select().from(connections).where(eq(connections.userId, user.id))
      : await db.select().from(connections);

    const connectedMap = new Map(
      userConnections.map((conn) => [`${conn.provider}:${conn.role}`, conn]),
    );

    // Build slots from all registered providers (checks both DB and .env)
    const available = new Set(await getAvailableProviderIds(db));
    const allSlots = [
      { provider: "google", role: "owner", label: "Google (Owner)" },
      { provider: "google", role: "agent", label: "Google (Agent)" },
      { provider: "github", role: "owner", label: "GitHub (Owner)" },
      { provider: "github", role: "agent", label: "GitHub (Agent)" },
      { provider: "discord", role: "owner", label: "Discord (Owner)" },
      { provider: "discord", role: "agent", label: "Discord (Agent)" },
    ];

    const serviceRows = allSlots
      .map((slot) => {
        const conn = connectedMap.get(`${slot.provider}:${slot.role}`);
        const isAvailable = available.has(slot.provider);
        if (conn) {
          return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>${escapeHtml(conn.accountLabel ?? "—")}</td>
            <td><span class="badge badge-connected">Connected</span></td>
            <td>
              <form method="POST" action="/api/connections/${escapeHtml(conn.id)}/delete">
                <button type="submit" class="btn btn-sm btn-danger">Disconnect</button>
              </form>
            </td>
          </tr>`;
        } else if (isAvailable) {
          return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>—</td>
            <td><span class="badge badge-disconnected">Not connected</span></td>
            <td>
              <a href="/oauth/${escapeHtml(slot.provider)}/start?role=${escapeHtml(slot.role)}" class="btn btn-sm btn-primary">Connect</a>
            </td>
          </tr>`;
        } else {
          return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>—</td>
            <td><span class="badge badge-warning">Not configured</span></td>
            <td><a href="/settings/providers" class="btn btn-sm btn-outline">Configure</a></td>
          </tr>`;
        }
      })
      .join("\n");

    const dashboardHtml = await readView("dashboard.html");
    const content = dashboardHtml
      .replace("{{user_email}}", escapeHtml(user?.email ?? "Owner (local)"))
      .replace("{{service_rows}}", serviceRows);

    const layout = await readView("layout.html");
    const html = layout
      .replace("{{title}}", "Aionima ID — Dashboard")
      .replace("{{content}}", content);

    return c.html(html);
  });

  return app;
}
