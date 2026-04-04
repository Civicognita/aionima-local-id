import { readFile } from "node:fs/promises";
import { join } from "node:path";

const VIEWS_DIR = join(process.cwd(), "src", "views");

export async function readView(name: string): Promise<string> {
  return readFile(join(VIEWS_DIR, name), "utf8");
}
