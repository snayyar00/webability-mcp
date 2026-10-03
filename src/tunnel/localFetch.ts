/**
 * Serving one request from the local dev server.
 *
 * Deliberately free of any transport dependency: this is the security-critical
 * half of the client — the part that decides what leaves the developer's
 * machine — and it should be testable without a WebSocket anywhere near it.
 */
import { localTargetUrl } from './requestGuard'

/** Cap on what one local response may return, matching the relay's own limit. */
const MAX_LOCAL_BYTES = 10 * 1024 * 1024
const LOCAL_TIMEOUT_MS = 15_000

/**
 * Serve ONE request from the local dev server.
 *
 * Exported for tests: the interesting cases here are a relay that misbehaves
 * and a dev server that is not running, and both should be provable without a
 * live socket.
 */
export async function serveLocalRequest(
  port: number,
  msg: { path: string; method?: string; headers?: Record<string, string> },
  fetchImpl: typeof fetch = fetch,
): Promise<{ status: number; headers: Record<string, string>; bodyBase64: string } | { error: string }> {
  let target: string
  try {
    // Throws on anything that is not a plain path.
    target = localTargetUrl(port, msg.path)
  } catch (err) {
    return { error: (err as Error).message }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), LOCAL_TIMEOUT_MS)
  try {
    const res = await fetchImpl(target, {
      method: msg.method === 'HEAD' ? 'HEAD' : 'GET',
      headers: msg.headers ?? {},
      redirect: 'manual',
      signal: controller.signal,
    })
    // Streamed, with a running total. `arrayBuffer()` downloads and allocates
    // the WHOLE response before any cap could be applied, so an unbounded local
    // endpoint exhausts this process's memory no matter what the cap says —
    // and a leaked credential can fire several of those at once. The limit has
    // to stop the transfer, not describe it afterwards.
    const chunks: Buffer[] = []
    let total = 0
    let oversized = false
    if (res.body) {
      for await (const chunk of res.body as any) {
        const buf = Buffer.from(chunk)
        total += buf.length
        if (total > MAX_LOCAL_BYTES) {
          // Return FIRST, abort after. Aborting while the async iterator is
          // still active makes its close step reject with AbortError, which
          // the catch below then reports as "is your dev server running?" —
          // a confusing wrong answer for a response that was simply too big.
          oversized = true
          break
        }
        chunks.push(buf)
      }
    }
    if (oversized) {
      controller.abort()
      return { error: 'local response too large' }
    }
    const buffer = Buffer.concat(chunks)
    // Node's fetch transparently decodes gzip/br but leaves the original
    // content-encoding and content-length in place. Forwarded as-is, the
    // caller tries to gunzip plain bytes and the scan sees a broken page.
    // safeResponseHeaders drops both; this keeps the client honest too.
    const headers: Record<string, string> = {}
    res.headers.forEach((value, key) => {
      const name = key.toLowerCase()
      if (name === 'content-encoding' || name === 'content-length') return
      headers[name] = value
    })
    return { status: res.status, headers, bodyBase64: buffer.toString('base64') }
  } catch (err) {
    // Almost always "nothing is listening on that port" — say so plainly
    // rather than leaking a stack to the relay.
    return { error: `could not reach http://127.0.0.1:${port} — is your dev server running? (${(err as Error).name})` }
  } finally {
    clearTimeout(timer)
  }
}
