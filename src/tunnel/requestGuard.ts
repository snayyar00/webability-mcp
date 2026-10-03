/**
 * What the public side of the relay will accept.
 *
 * This is the file that decides whether we built a scan path or an open proxy
 * into people's private networks. Everything here is a refusal.
 */
export const TUNNEL_SECRET_HEADER = 'x-webability-tunnel-secret'

/** Only what a page scan needs. A tunnel is not a general-purpose proxy. */
export const ALLOWED_METHODS = new Set(['GET', 'HEAD'])

/**
 * Headers never forwarded to the developer's machine.
 *
 * Our own auth must not be replayed inward: a dev server that happens to read
 * Authorization would receive the caller's WebAbility token, and the tunnel
 * secret must never leave the relay at all.
 */
export const STRIPPED_REQUEST_HEADERS = new Set(['authorization', 'cookie', TUNNEL_SECRET_HEADER, 'x-webability-token', 'proxy-authorization'])

export interface InboundRequest {
  method: string
  /** Path with query, as it arrived: "/t/<id>/dashboard?x=1". */
  url: string
  headers: Record<string, string | string[] | undefined>
}

export type GuardResult = { ok: true; tunnelId: string; secret: string; forwardPath: string } | { ok: false; status: number; reason: string }

/**
 * Parse and vet one inbound request.
 *
 * Refuses before any tunnel lookup, so a malformed or unauthenticated request
 * never reaches the registry and cannot be used to probe it.
 */
export function guardInbound(req: InboundRequest): GuardResult {
  if (!ALLOWED_METHODS.has(req.method.toUpperCase())) {
    return { ok: false, status: 405, reason: 'only GET and HEAD are forwarded' }
  }

  const match = /^\/t\/([0-9a-f]{32})(\/[^\s]*)?$/.exec(req.url.split('#')[0])
  if (!match) return { ok: false, status: 404, reason: 'not a tunnel path' }

  const secret = headerValue(req.headers, TUNNEL_SECRET_HEADER)
  // No secret, no lookup. The URL is not a credential — see tunnelRegistry.
  if (!secret) return { ok: false, status: 401, reason: `missing ${TUNNEL_SECRET_HEADER}` }

  const rest = match[2] ?? '/'
  if (hasTraversal(rest)) return { ok: false, status: 400, reason: 'path traversal' }

  return { ok: true, tunnelId: match[1], secret, forwardPath: rest }
}

function headerValue(headers: InboundRequest['headers'], name: string): string {
  const raw = headers[name] ?? headers[name.toLowerCase()]
  if (Array.isArray(raw)) return raw[0] ?? ''
  return typeof raw === 'string' ? raw : ''
}

/** Strip what must never cross into a developer's network. */
export function forwardableHeaders(headers: InboundRequest['headers']): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) continue
    if (typeof value === 'string') out[key] = value
  }
  return out
}

/**
 * The URL the CLIENT is allowed to fetch, given its registered port.
 *
 * Built on the client from its own registration, never from anything the relay
 * sends — that is what stops a compromised or malicious relay from turning a
 * tunnel into a request for 169.254.169.254 or a neighbouring service. The
 * host is loopback and the port is the one the developer typed, always.
 */
export function localTargetUrl(port: number, forwardPath: string): string {
  // Treat the path as a path, never as a URL. Without this, a relay that sent
  // "http://169.254.169.254/latest/meta-data/" would have the client fetch
  // cloud metadata from inside the developer's network and hand it back —
  // the relay becoming the SSRF vector it exists to avoid.
  const raw = String(forwardPath ?? '')
  if (/^[a-zA-Z][\w+.-]*:/.test(raw) || raw.startsWith('//')) {
    throw new Error('tunnel target must be a path, not a URL')
  }
  // Checked AGAIN here, not only at the relay's ingress. The relay is the
  // thing this client is supposed to distrust: a compromised or buggy one can
  // send any path it likes, and `/..%2f..%2fsecret` would otherwise be fetched
  // straight off the developer's machine. The ingress check protects against
  // outsiders; this one protects against the relay itself.
  if (hasTraversal(raw)) {
    throw new Error('tunnel target must not traverse outside the served path')
  }
  const path = raw.startsWith('/') ? raw : `/${raw}`
  return `http://127.0.0.1:${port}${path}`
}

/**
 * Headers we refuse to copy from the developer's machine onto OUR origin.
 *
 * Hop-by-hop headers break the connection if forwarded, and the security
 * headers matter more: a tunnel client that could set `set-cookie` or
 * `access-control-allow-origin` would be scripting a response from
 * tunnel.webability.io, an origin the browser trusts more than its own.
 */
export const STRIPPED_RESPONSE_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'set-cookie',
  'set-cookie2',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'strict-transport-security',
  // Recomputed by us: the body was decoded and re-encoded on the way through.
  'content-encoding',
  'content-length',
])

/** A status code Node will accept. Anything else is the client misbehaving. */
export function safeStatus(raw: unknown): number {
  const status = Number(raw)
  return Number.isInteger(status) && status >= 100 && status <= 599 ? status : 502
}

/**
 * Sanitise headers coming back from a developer's machine.
 *
 * Header VALUES are the dangerous part: a value containing CR or LF splits the
 * response, letting an untrusted machine inject a whole second response on our
 * origin. Node throws on some of these, but not reliably enough to be the only
 * defence.
 */
export function safeResponseHeaders(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value !== 'string') continue
    const name = key.toLowerCase()
    if (STRIPPED_RESPONSE_HEADERS.has(name)) continue
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) continue
    if (/[\r\n\0]/.test(value)) continue
    out[name] = value
  }
  return out
}

/**
 * Does this path try to escape, in any encoding?
 *
 * A literal `..` check is not enough. `%2e%2e%2f` survives it, and any static
 * middleware that percent-decodes before resolving (sirv, serve-static) then
 * serves files from outside the project root — so a secret holder reads
 * arbitrary files off the developer's machine, which is the precise thing this
 * guard exists to stop.
 *
 * Decoding is done repeatedly because `%252e` decodes to `%2e` and then to `.`.
 * A path that will not decode at all is refused rather than guessed at.
 */
export function hasTraversal(path: string): boolean {
  let current = path
  for (let i = 0; i < 3; i++) {
    if (current.includes('..')) return true
    // Backslashes are separators on Windows dev machines.
    if (/\\/.test(current)) return true
    let decoded: string
    try {
      decoded = decodeURIComponent(current)
    } catch {
      // Malformed encoding: refuse rather than forward something we cannot read.
      return true
    }
    if (decoded === current) break
    current = decoded
  }
  return current.includes('..')
}
