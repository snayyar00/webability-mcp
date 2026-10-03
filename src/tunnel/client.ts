/**
 * The tunnel client — runs on the developer's machine.
 *
 * Its job is to be suspicious of the relay. The relay sends a path and this
 * fetches it from 127.0.0.1 on ONE port: the one the developer typed. Nothing
 * the relay says can change the host or the port, which is what keeps a tunnel
 * from becoming a general-purpose hole into their network.
 */
import { WebSocket } from 'ws'

import { serveLocalRequest } from './localFetch'

export interface TunnelHandle {
  url: string
  secret: string
  secretHeader: string
  close(): void
}

export interface TunnelClientOptions {
  relayUrl: string
  token: string
  port: number
  /** Injected for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch
  onStatus?: (message: string) => void
  /**
   * The tunnel died AFTER it was open. Separate from the promise, which has
   * already settled — without this the caller cannot tell a deliberate close
   * from an expiry, and a long-running job never learns it lost the tunnel.
   */
  onClosed?: (info: { code: number; reason: string }) => void
}

/** Open a tunnel and keep it serving until closed. */
/**
 * Is this a relay we are willing to hand the user's token to?
 *
 * `--relay` takes a URL and the token rides on it as a Bearer header, so a
 * doctored command line — a typosquatted host, a copy-pasted "fix" from a
 * forum — exfiltrates a live WebAbility credential. Plaintext `ws://` would
 * also put it on the wire in the clear.
 *
 * Loopback is allowed because that is how this is developed and tested, and a
 * relay on your own machine is not an exfiltration path.
 */
/** The relay we will hand a token to. Overridable for self-hosting. */
export const TRUSTED_RELAY_HOST = (process.env.WEBABILITY_TUNNEL_HOST || 'tunnel.webability.io').toLowerCase()

/** Node's WHATWG URL keeps the brackets on IPv6 hostnames, so '[::1]' is the
 *  form that actually appears — a bare '::1' arm would never match. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

export function assertUsableRelay(rawUrl: string): void {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new Error(`--relay is not a valid URL: ${rawUrl}`)
  }
  const host = url.hostname.toLowerCase()
  const loopback = LOOPBACK_HOSTS.has(host)
  // Scheme AND host. Checking only the scheme was not an allowlist at all:
  // wss://tunne1.webability.io is perfectly valid TLS to a typosquat, and the
  // token would have gone straight to it. Exact match, no suffix test —
  // "endsWith('.webability.io')" is defeated by webability.io.evil.com.
  if (host !== TRUSTED_RELAY_HOST && !loopback) {
    throw new Error(`refusing to send your token to ${url.origin} — the relay must be ${TRUSTED_RELAY_HOST} (or localhost for development)`)
  }
  if (url.protocol === 'wss:') return
  if (url.protocol === 'ws:' && loopback) return
  throw new Error(`refusing to send your token over ${url.protocol}// — a relay must be wss:// (ws:// is allowed only on localhost)`)
}

export function openTunnel(opts: TunnelClientOptions): Promise<TunnelHandle> {
  const { relayUrl, token, port, fetchImpl = fetch, onStatus, onClosed } = opts
  return new Promise((resolve, reject) => {
    // Inside the promise, so this REJECTS rather than throwing synchronously.
    // A function returning a Promise that sometimes throws instead forces
    // every caller to write both a try/catch and a .catch, and the one place
    // that forgets prints a stack trace instead of the message.
    try {
      assertUsableRelay(relayUrl)
    } catch (err) {
      reject(err)
      return
    }

    let registered = false
    const socket = new WebSocket(`${relayUrl.replace(/\/$/, '')}/agent`, { headers: { Authorization: `Bearer ${token}` } })

    socket.on('open', () => socket.send(JSON.stringify({ type: 'register', port })))

    socket.on('message', async (raw: any) => {
      let msg: any
      try {
        msg = JSON.parse(String(raw))
      } catch {
        return
      }

      if (msg.type === 'registered') {
        registered = true
        resolve({
          url: msg.url,
          secret: msg.secret,
          secretHeader: msg.secretHeader,
          close: () => socket.close(),
        })
        return
      }

      if (msg.type === 'error') {
        reject(new Error(msg.message))
        return
      }

      if (msg.type === 'request') {
        onStatus?.(`${msg.method} ${msg.path}`)
        const result = await serveLocalRequest(port, msg, fetchImpl)
        socket.send(JSON.stringify({ type: 'response', requestId: msg.requestId, ...result }))
      }
    })

    socket.on('error', (err: Error) => {
      if (registered) {
        onStatus?.(`tunnel error: ${err.message}`)
        return
      }
      reject(err)
    })
    socket.on('close', (code: number, reason: Buffer) => {
      // AFTER a successful registration, reject() is a no-op: the promise is
      // settled, nothing prints, and the process drains and exits 0. A tunnel
      // that dies mid-session — expired, revoked, relay restarted — would look
      // like a clean finish, and a CI job depending on it would go green while
      // the scans behind it silently stopped working.
      if (registered) {
        onClosed?.({ code, reason: String(reason) })
        return
      }
      if (code === 4401) reject(new Error('the relay rejected your token — run `webability login` and try again'))
      // An auth-service outage is not a bad token. Telling someone to rotate a
      // working credential while the fault is ours wastes their afternoon.
      else if (code === 4503) reject(new Error('the WebAbility auth service is unreachable — your token is fine, try again shortly'))
      else if (code === 4408) reject(new Error('the tunnel expired — open a new one'))
      else if (code === 4400) reject(new Error(String(reason)))
      // Any other close before registration must still settle, or the caller
      // waits forever: a relay restart (4409), a dropped connection (1006).
      else if (code === 4409) reject(new Error('the relay is restarting — try again in a few seconds'))
      else reject(new Error(`the relay closed the connection before the tunnel opened (${code})`))
    })
  })
}
