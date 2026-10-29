/**
 * Request-body caps for the hosted HTTP server (#199). Bodies used to be
 * buffered in full, then parsed, before auth and rate limiting: one anonymous
 * 256 MB POST sat in the shared heap of the single process every tenant uses.
 */
import type { IncomingMessage } from 'node:http'

/** /mcp: a JSON-RPC call. scan_html carries page HTML, so allow a large page. Override: MCP_MAX_BODY_BYTES. */
export const MCP_MAX_BODY_BYTES = positiveInt(process.env.MCP_MAX_BODY_BYTES) ?? 5 * 1024 * 1024

/** OAuth endpoints (/register, /token, /authorize/*): small JSON or form bodies. */
export const OAUTH_MAX_BODY_BYTES = 64 * 1024

function positiveInt(raw: string | undefined): number | undefined {
  const n = Number(raw)
  return Number.isInteger(n) && n > 0 ? n : undefined
}

export class BodyTooLargeError extends Error {
  constructor(readonly limit: number) {
    super(`request body is larger than ${limit} bytes`)
    this.name = 'BodyTooLargeError'
  }
}

/** True if the declared Content-Length is over `limit` — refuse before reading a byte. */
export function declaredTooLarge(req: IncomingMessage, limit: number): boolean {
  const raw = req.headers['content-length']
  if (raw === undefined) return false
  const n = Number(raw)
  return !Number.isFinite(n) || n > limit
}

/**
 * Read the body, stopping at `limit` bytes (chunked bodies have no
 * Content-Length to check first). On overflow the stream is paused, not
 * destroyed, so the caller can still answer 413 (send it with
 * `Connection: close`).
 */
export function readBodyCapped(req: IncomingMessage, limit: number): Promise<Buffer> {
  if (declaredTooLarge(req, limit)) return Promise.reject(new BodyTooLargeError(limit))
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    const onData = (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        cleanup()
        req.pause()
        reject(new BodyTooLargeError(limit))
        return
      }
      chunks.push(chunk)
    }
    const onEnd = () => {
      cleanup()
      resolve(Buffer.concat(chunks))
    }
    const onError = (err: Error) => {
      cleanup()
      reject(err)
    }
    const cleanup = () => {
      req.off('data', onData)
      req.off('end', onEnd)
      req.off('error', onError)
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
  })
}
