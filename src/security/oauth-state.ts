/**
 * HMAC-signed OAuth state parameters.
 *
 * Prevents state forgery — an attacker can't craft a valid state
 * without knowing the server's ENCRYPTION_KEY.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

function getHmacKey(): string {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error("ENCRYPTION_KEY is required for OAuth state signing");
  }
  return key;
}

/**
 * Create a signed state string: base64url(payload).signature
 */
export function signOAuthState(payload: Record<string, unknown>): string {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", getHmacKey())
    .update(data)
    .digest("base64url");
  return `${data}.${sig}`;
}

/**
 * Verify and parse a signed state string. Returns null if invalid.
 */
export function verifyOAuthState<T = Record<string, unknown>>(state: string): T | null {
  const dotIndex = state.lastIndexOf(".");
  if (dotIndex === -1) return null;

  const data = state.slice(0, dotIndex);
  const sig = state.slice(dotIndex + 1);

  const expectedSig = createHmac("sha256", getHmacKey())
    .update(data)
    .digest("base64url");

  // Timing-safe comparison
  const sigBuf = Buffer.from(sig, "base64url");
  const expectedBuf = Buffer.from(expectedSig, "base64url");

  if (sigBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    return JSON.parse(Buffer.from(data, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}
