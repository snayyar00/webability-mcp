/**
 * Keep a tunnel up across relay restarts.
 *
 * The relay redeploys on every webability-platform merge. On shutdown it
 * closes each agent with RELAY_RESTART_CODE; that code, and only that code,
 * means "reconnect". Every other close (expiry, revoked token, a network that
 * really died) stays final, so a CI job depending on the tunnel still fails.
 *
 * Kept out of client.ts on purpose: that file is a byte-for-byte copy of the
 * relay's client (tunnel-client-parity.test.ts), and this policy is the CLI's.
 */
import type { TunnelHandle } from './client'

/** Mirrors RELAY_RESTART_CODE in platform/tunnel-relay/src/server.ts. */
export const RELAY_RESTART_CODE = 4409

const MAX_DELAY_MS = 30_000

export type CloseInfo = { code: number; reason: string }

export type TunnelEnd = { reason: 'closed' | 'reconnect-failed'; code: number; message: string }

export interface KeepTunnelOptions {
  /** Open one tunnel; call onClosed if it dies after opening. Rejects on a failed open. */
  open: (onClosed: (info: CloseInfo) => void) => Promise<TunnelHandle>
  /** A tunnel is serving. `reconnect` is true after a relay restart: the URL and secret are new. */
  onOpened: (tunnel: TunnelHandle, reconnect: boolean) => void
  onRetry?: (attempt: number, delayMs: number, error: string) => void
  sleep?: (ms: number) => Promise<void>
  /** Reconnect attempts per restart before giving up. */
  maxAttempts?: number
  baseDelayMs?: number
  /** Deadline for one reconnect open: a relay that accepts and never answers must not stall the retries. */
  attemptTimeoutMs?: number
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

/**
 * Resolves only when the tunnel is gone for good. A failure on the FIRST open
 * rejects, unretried: a bad token or flag should fail fast, not back off.
 */
export async function keepTunnel(opts: KeepTunnelOptions): Promise<TunnelEnd> {
  const { open, onOpened, onRetry, sleep = realSleep, maxAttempts = 8, baseDelayMs = 1_000, attemptTimeoutMs = 30_000 } = opts

  const serve = async (reconnect: boolean): Promise<CloseInfo> => {
    let closed!: (info: CloseInfo) => void
    const whenClosed = new Promise<CloseInfo>((r) => (closed = r))
    const opening = open((info) => closed(info))
    const tunnel = reconnect ? await withDeadline(opening, attemptTimeoutMs) : await opening
    onOpened(tunnel, reconnect)
    return whenClosed
  }

  let last = await serve(false)
  for (;;) {
    if (last.code !== RELAY_RESTART_CODE) return { reason: 'closed', code: last.code, message: last.reason }
    let error = ''
    let next: CloseInfo | null = null
    for (let attempt = 1; attempt <= maxAttempts && !next; attempt++) {
      const delay = Math.min(baseDelayMs * 2 ** (attempt - 1), MAX_DELAY_MS)
      if (attempt > 1) onRetry?.(attempt, delay, error)
      await sleep(delay)
      try {
        next = await serve(true)
      } catch (err) {
        error = (err as Error).message
      }
    }
    if (!next) return { reason: 'reconnect-failed', code: last.code, message: error }
    last = next
  }
}

/**
 * Reject when `opening` misses its deadline. openTunnel cannot be cancelled,
 * so a tunnel that opens after the deadline is closed rather than left
 * serving a URL nobody printed.
 */
function withDeadline(opening: Promise<TunnelHandle>, ms: number): Promise<TunnelHandle> {
  let timer: ReturnType<typeof setTimeout>
  let late = false
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      late = true
      reject(new Error(`reconnect attempt timed out after ${Math.round(ms / 1000)} s`))
    }, ms)
  })
  opening.then(
    (t) => {
      if (late) t.close()
    },
    () => {},
  )
  return Promise.race([opening, deadline]).finally(() => clearTimeout(timer))
}
