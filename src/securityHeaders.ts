/**
 * Security headers for every response the hosted transport sends (#1457).
 *
 * Set on the ServerResponse BEFORE anything writes a status line, so they reach
 * every path — the JSON-RPC answers, the CORS preflight, the plain-text
 * challenge, the redirects, and the OAuth pages owned by oauth.ts. `setHeader`
 * values survive a later `writeHead(status, {...})`: Node merges the two, and
 * nothing here collides with a header those call sites already set.
 *
 * Deliberately NOT sent: Cross-Origin-Resource-Policy / Cross-Origin-Embedder-
 * Policy. This endpoint exists to be called cross-origin by MCP clients, and
 * COEP would refuse the requests those clients make.
 *
 * CSP is harmless on a JSON body (it is only enforced on a document), so the
 * locked-down policy is the default. The one exception is our own HTML — the
 * OAuth authorize/status pages — which ship inline <style>/<script> and POST to
 * this same origin. Earning 'unsafe-inline' there is buying nothing: the pages
 * are static templates with JSON-escaped parameters, so there is no attacker
 * markup for the browser to distinguish from ours.
 */
import type { ServerResponse } from 'http'

/** Locked down: nothing may load, nowhere may frame us. */
export const LOCKED_CSP = "default-src 'none'; frame-ancestors 'none'"

/** What the OAuth pages need: their own inline style/script and same-origin fetch. */
export const PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

/** Apply the security headers. `html` for a document this server renders itself. */
export function setSecurityHeaders(res: ServerResponse, { html = false }: { html?: boolean } = {}): void {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Content-Security-Policy', html ? PAGE_CSP : LOCKED_CSP)
}
