/**
 * Single-source version string for Local-ID.
 *
 * Read from package.json at module-load time so every surface —
 * `/health`, the layout footer badge, any diagnostic log — reports
 * the exact same string without drift. Imported by callers rather
 * than re-read per request so we don't hit the filesystem on every
 * /health poll.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// loader.ts uses the same trick — resolve relative to this file so it
// works in both dev (src/) and container (dist/) layouts. package.json
// sits at the repo root, two levels up from src/ or dist/.
const here = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(here, "..", "package.json");

let version = "unknown";
try {
  const raw = readFileSync(pkgPath, "utf8");
  const parsed = JSON.parse(raw) as { version?: string };
  if (typeof parsed.version === "string" && parsed.version.length > 0) {
    version = parsed.version;
  }
} catch {
  // Non-fatal — fall back to "unknown" so pages still render
}

export const VERSION = version;
