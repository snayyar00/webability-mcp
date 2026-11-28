/**
 * Validate a caller's WebAbility token against the API, through a
 * validated-token cache.
 *
 * Only 401/403 from the API are a verdict on the token ('invalid').
 * 'unavailable' = no verdict: network error, 5xx, throttling (429) or another
 * transient status (408, 425, ...). Answering that with 401 would make Claude
 * Code mark the server needs-auth (zero tools in later sessions) and claude.ai
 * invalidate the connector, for every signed-in user, during an API outage.
 *
 * Kept out of http.ts because that module starts an HTTP server on import and
 * cannot be unit-tested.
 */
import type { TokenCache } from './tokenCache.js'
import { TOKEN_TTL_MS } from './tokenCache.js'

export type TokenCheck = { state: 'valid' | 'invalid' } | { state: 'unavailable'; retryAfter: string }

const DEFAULT_RETRY_AFTER_S = '30'

/** Upstream Retry-After when it is delta-seconds or an HTTP date; otherwise our default. */
export function retryAfterFrom(res: Response): string {
  const raw = (res.headers.get('retry-after') || '').trim()
  if (/^\d{1,6}$/.test(raw)) return raw
  const when = Date.parse(raw)
  if (!Number.isNaN(when)) return String(Math.max(1, Math.ceil((when - Date.now()) / 1000)))
  return DEFAULT_RETRY_AFTER_S
}

export async function checkToken(apiUrl: string, cache: TokenCache, token: string): Promise<TokenCheck> {
  if (!token) return { state: 'invalid' }
  if (cache.get(token) !== undefined) return { state: 'valid' }
  try {
    const res = await fetch(`${apiUrl}/cli/whoami`, { headers: { Authorization: `Bearer ${token}` } })
    if (res.ok) {
      cache.set(token, Date.now() + TOKEN_TTL_MS)
      return { state: 'valid' }
    }
    if (res.status === 401 || res.status === 403) return { state: 'invalid' }
    return { state: 'unavailable', retryAfter: retryAfterFrom(res) }
  } catch {
    return { state: 'unavailable', retryAfter: DEFAULT_RETRY_AFTER_S }
  }
}
