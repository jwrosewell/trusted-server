// Gathers the client evidence 51Degrees needs and leaves it where the server
// will find it on the next request.
//
// This module makes no network call of its own. The appliance already calls the
// 51Degrees service from the server, and everything it can learn from a
// User-Agent alone it learns there. What a server cannot see is the screen and
// the high entropy client hints, because those exist only in the browser. So
// this puts them in `51D_` prefixed cookies, which the browser sends on every
// later request, and the server adds them to the call it was going to make
// anyway.
//
// The cookie names and the encoding are not ours. They are the ones the
// service's own JavaScript writes, taken from the `ScreenPixelsWidthJavascript`,
// `ScreenPixelsHeightJavascript` and `JavascriptGetHighEntropyValues`
// properties it returns. Matching them means the server side reads the evidence
// whether it was this module or the vendor's own bundle that wrote it.
//
// Session storage is written as well, which is belt and braces rather than
// duplication. The cookie is the part that travels to the server. The session
// storage copy is what this module reads on the next page view so it does not
// ask the browser the same questions again, and it survives in contexts where a
// cookie write is refused.
//
// Nothing here runs unless the permission to store on the device is set, which
// is the same permission the server-side identity provider declares and the
// same check the client-cycle Edge Cookie module makes. The page's half of one
// decision, not a substitute for the server's.
import { log } from '../../core/log';

// The `51D_` prefix belongs to 51Degrees and sits outside the `ts-` namespace
// Trusted Server reserves for its own cookies, so there is no collision.
const COOKIE_SCREEN_WIDTH = '51D_ScreenPixelsWidth';
const COOKIE_SCREEN_HEIGHT = '51D_ScreenPixelsHeight';
const COOKIE_HIGH_ENTROPY = '51D_GetHighEntropyValues';

// Where the same values are kept for this module's own use. Session rather than
// local storage, matching the vendor bundle, because this is evidence about the
// current browsing session and not something to keep indefinitely.
const STORAGE_KEY = '51D_Evidence';

// The hints the service asks for, from the `JavascriptGetHighEntropyValues`
// property it returns. Asking for more than the service reads would collect
// more about the visitor than the answer needs.
const HIGH_ENTROPY_HINTS = ['model', 'platform', 'platformVersion', 'fullVersionList'];

// Storing on the device is exactly what writing these cookies is, so this
// module requires the same permission the server-side provider does. A Rust
// test asserts the two stay in sync.
const REQUIRED_PERMISSION = 'necessary.operations.storage';

/**
 * Whether the permission this module requires is set in the page state the edge
 * injected.
 *
 * With no permission state on the page there is nothing to check against, so
 * the answer is no. Guessing yes would write to a visitor's device on the
 * strength of a missing value.
 */
export async function requiredPermissionIsSet(): Promise<boolean> {
  const whenPermissions = window.tsjs?.whenPermissions;
  if (typeof whenPermissions !== 'function') {
    log.warn('51degrees: no permission state on the page, gathering nothing');
    return false;
  }
  const snapshot = await whenPermissions();
  return Array.isArray(snapshot?.set) && snapshot.set.includes(REQUIRED_PERMISSION);
}

/**
 * Writes one first-party cookie for the current path.
 *
 * `Secure` is set only on a secure page, because a browser discards a `Secure`
 * cookie written over plain HTTP and the appliance is routinely run that way
 * for local work. `SameSite=Lax` because this is evidence the first party sends
 * to itself on its own navigations.
 */
export function writeCookie(name: string, value: string): void {
  const secure = location.protocol === 'https:' ? '; Secure' : '';
  // Written raw, not percent encoded, because the vendor's own JavaScript
  // writes it raw and the server has to read either. The values are digits or
  // base64, and base64's `+`, `/` and `=` are all legal cookie characters, so
  // nothing here needs escaping. Encoding would make our cookies readable and
  // the vendor's not, which is the opposite of the point.
  document.cookie = `${name}=${value}; Path=/; SameSite=Lax${secure}`;
}

/**
 * The evidence this module gathered earlier in the session, or `null`.
 *
 * Storage access throws rather than returning nothing in some contexts, a
 * private window among them, so every read is guarded.
 */
export function readStoredEvidence(): Record<string, string> | null {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    return stored ? (JSON.parse(stored) as Record<string, string>) : null;
  } catch {
    return null;
  }
}

/** Keeps the evidence for the rest of the session. */
export function storeEvidence(evidence: Record<string, string>): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(evidence));
  } catch {
    // Storage being unavailable costs this module its cache and nothing else,
    // because the cookies are what the server reads.
  }
}

/**
 * Asks the browser for the high entropy client hints, base64 encoded the way
 * the service expects them.
 *
 * Returns `null` on a browser without the API, which is every browser outside
 * the Chromium family, and on a rejection. Neither is a failure: the server
 * still has the User-Agent and answers from that.
 */
export async function highEntropyValues(): Promise<string | null> {
  const agentData = (
    navigator as Navigator & {
      userAgentData?: { getHighEntropyValues(hints: string[]): Promise<unknown> };
    }
  ).userAgentData;
  if (!agentData || typeof agentData.getHighEntropyValues !== 'function') {
    return null;
  }
  try {
    const values = await agentData.getHighEntropyValues(HIGH_ENTROPY_HINTS);
    return btoa(JSON.stringify(values));
  } catch (error) {
    log.warn('51degrees: the browser refused the high entropy values', error);
    return null;
  }
}

/**
 * Gathers what only the browser knows and leaves it for the server.
 *
 * Returns what was written, or `null` when nothing was, so a caller and a test
 * can tell the difference between "gathered nothing" and "did not run".
 */
export async function gatherEvidence(): Promise<Record<string, string> | null> {
  if (typeof document === 'undefined' || typeof window === 'undefined') {
    return null;
  }
  if (!(await requiredPermissionIsSet())) {
    log.info('51degrees: permission to store on the device is not set, gathering nothing');
    return null;
  }

  const evidence: Record<string, string> = {};

  // The screen is read every time rather than taken from storage, because a
  // phone that has been rotated since the last page view has a different one
  // and a stale value is worse than none.
  if (typeof screen !== 'undefined') {
    evidence[COOKIE_SCREEN_WIDTH] = String(screen.width);
    evidence[COOKIE_SCREEN_HEIGHT] = String(screen.height);
  }

  // The client hints do not change within a session and the call is not free,
  // so a stored answer is reused.
  const stored = readStoredEvidence();
  const hints = stored?.[COOKIE_HIGH_ENTROPY] ?? (await highEntropyValues());
  if (hints) {
    evidence[COOKIE_HIGH_ENTROPY] = hints;
  }

  if (Object.keys(evidence).length === 0) {
    return null;
  }

  for (const [name, value] of Object.entries(evidence)) {
    writeCookie(name, value);
  }
  storeEvidence(evidence);
  log.info(`51degrees: gathered ${Object.keys(evidence).length} pieces of client evidence`);
  return evidence;
}

if (typeof window !== 'undefined') {
  void gatherEvidence();
}
