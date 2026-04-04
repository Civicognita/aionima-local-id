/**
 * HTML escaping to prevent XSS in server-rendered templates.
 */

const ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
  "`": "&#96;",
};

const ESCAPE_RE = /[&<>"'/`]/g;

export function escapeHtml(str: string): string {
  return str.replace(ESCAPE_RE, (ch) => ESCAPE_MAP[ch]!);
}
