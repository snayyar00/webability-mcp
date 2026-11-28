/**
 * A bounded, TTL'd set of tokens the platform has already validated.
 *
 * Two properties matter and neither is free with a bare Map:
 *
 *  - It is bounded. `http.ts` calls `set()` only for tokens the platform
 *    validated, but entries for expired valid tokens were never removed, so
 *    the map grew with every distinct valid token for the life of the process.
 *  - An expired entry is absent, not merely stale. Callers use `has()` to
 *    decide "this token is known good, skip the platform call", so an expired
 *    entry that still answers true is a token that never has to be re-checked.
 *
 * Kept out of http.ts because that module starts an HTTP server on import and
 * cannot be unit-tested.
 */
export interface TokenCache {
  /** The expiry for a live token, or undefined. Drops the entry if it expired. */
  get(token: string): number | undefined
  /** True only for a live token. Drops the entry if it expired. */
  has(token: string): boolean
  /** Remember `token` as valid until `expiresAt` (epoch ms). */
  set(token: string, expiresAt: number): void
  delete(token: string): void
  readonly size: number
}

export interface TokenCacheOptions {
  /** Maximum live entries. The oldest is evicted when a new key would exceed it. */
  max: number
  /** Clock, injectable so tests do not sleep. */
  now?: () => number
}

export function createTokenCache({ max, now = Date.now }: TokenCacheOptions): TokenCache {
  const entries = new Map<string, number>()

  const live = (token: string): number | undefined => {
    const exp = entries.get(token)
    if (exp === undefined) return undefined
    if (exp > now()) return exp
    entries.delete(token)
    return undefined
  }

  return {
    get: live,
    has: (token) => live(token) !== undefined,
    set: (token, expiresAt) => {
      // Map.set on an existing key keeps its original insertion position, so
      // refreshing a live token must not count as a new entry — otherwise a
      // busy token would evict a different one on every refresh.
      if (!entries.has(token) && entries.size >= max) {
        const oldest = entries.keys().next().value
        if (oldest !== undefined) entries.delete(oldest)
      }
      entries.set(token, expiresAt)
    },
    delete: (token) => void entries.delete(token),
    get size() {
      return entries.size
    },
  }
}

/**
 * How long a platform "this token is valid" answer is trusted. Short, because
 * revocation is only noticed on the next platform round-trip.
 */
export const TOKEN_TTL_MS = 5 * 60 * 1000

/**
 * The process-wide cache. One instance so that a refusal seen by a tool call
 * (`server.ts`, `account.ts`) can evict the entry the HTTP gate (`http.ts`)
 * would otherwise trust for the rest of the TTL.
 */
export const validatedTokens = createTokenCache({ max: 10_000 })

/**
 * A platform call made with `token` answered 401/403, so the token is no
 * longer known good. The next request re-validates it against the platform
 * instead of trusting a cached answer for up to TOKEN_TTL_MS — that is the
 * revocation window this closes.
 *
 * Deliberately evicts only: 403 can be a plan or ownership refusal on a token
 * that is still authentic, so marking it rejected would tell a signed-in user
 * to sign in again. One extra `/cli/whoami` is the whole cost.
 */
export function forgetValidatedToken(token: string): void {
  if (token) validatedTokens.delete(token)
}
