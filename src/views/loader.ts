import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "../version.js";

// Resolve relative to this loader file so it works in both environments:
//   - dev (tsx): loader.ts sits next to the .html files in src/views/
//   - prod (Docker): loader.js sits next to the .html files in dist/views/
// `process.cwd()` isn't stable — the container sets workdir to /app, so
// `process.cwd()/src/views` 404s at runtime against the real `/app/dist/views`.
const VIEWS_DIR = dirname(fileURLToPath(import.meta.url));

export async function readView(name: string): Promise<string> {
  const raw = await readFile(join(VIEWS_DIR, name), "utf8");
  // Substitute `{{version}}` in any view (currently only layout.html uses it
  // for the bottom-right badge). Safe no-op for files without the token.
  return raw.replaceAll("{{version}}", VERSION);
}
