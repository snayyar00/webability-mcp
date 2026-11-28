/**
 * The hosted edge's answer to a scan_html call that the shared in-process engine
 * cannot start: one jsdom document per process, so a call past the queue depth
 * would wait behind an unknown number of multi-second scans.
 *
 * This lives apart from http.ts because http.ts starts listening on import. The
 * shaping of the refusal — batch stays a batch, /mcp/apps gets a tool result
 * instead of a status — is the part that must be pinned by a test.
 */
import { calledTools } from './anonGate.js'
import { scanHtmlQueue } from './fastScan.js'

export interface QueueSnapshot {
  depth: number
  limit: number
  full: boolean
  retryAfterSeconds: number
}

/**
 * Whether the body calls scan_html in a way that needs the engine thread.
 * engine:"browser" scans run their own page, so they are not refused here.
 */
function scanHtmlNeedsEngine(body: unknown): boolean {
  return calledTools(body).some((call) => {
    if (call.name !== 'scan_html') return false
    const args = call.args
    const engine = typeof args === 'object' && args !== null && 'engine' in args ? args.engine : undefined
    return engine !== 'browser'
  })
}

/** Every message in the body that carries an id — the only ones a client can match to a reply. */
function answerable(body: unknown): { id: unknown; method?: unknown }[] {
  return (Array.isArray(body) ? body : [body]).filter(
    (m): m is { id: unknown; method?: unknown } =>
      typeof m === 'object' && m !== null && 'id' in m,
  )
}

/**
 * A JSON-RPC reply per message in the body. A batch stays a batch: a client that
 * pipelines two tool calls is not left with a half-answered body. The status and
 * `Retry-After` carry the transport-level signal; this says which tool and how
 * long.
 *
 * /mcp/apps (ChatGPT) gets an isError tool result instead — the same choice the
 * anonymous cap makes there — because the Apps SDK has no retry-on-status
 * behavior and surfaces a non-200 as a dead connector rather than a message the
 * model can read.
 */
function busyResponse(body: unknown, text: string, retryAfterSeconds: number, apps: boolean): unknown {
  const error = { code: -32002, message: text, data: { retryAfterSeconds } }
  const replies = answerable(body).map((m) =>
    apps && m.method === 'tools/call'
      ? { jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text }], isError: true } }
      : { jsonrpc: '2.0', id: m.id, error },
  )
  return Array.isArray(body) ? replies : (replies[0] ?? { jsonrpc: '2.0', id: null, error })
}

export interface BusyRefusal {
  status: number
  retryAfterSeconds: number
  body: unknown
}

/**
 * The refusal for this request, or null when the engine has room. Called before
 * the SDK sees the body, so the caller learns the wait from the protocol rather
 * than only from prose. The tool handler applies the same cap for stdio.
 */
export function scanHtmlBusyRefusal(body: unknown, apps: boolean, queue: QueueSnapshot = scanHtmlQueue()): BusyRefusal | null {
  if (!queue.full || !scanHtmlNeedsEngine(body)) return null
  const text =
    `scan_html is at capacity: ${queue.depth} in-process scan(s) already running or queued on this server ` +
    `(the jsdom engine scans one document at a time). Server busy — retry in ${queue.retryAfterSeconds}s, ` +
    'or use scan_page on the URL (or scan_html with engine:"browser").'
  // 503 is HTTP-retriable by every client library; a 200 + isError is what the
  // Apps SDK can actually show the model.
  return {
    status: apps ? 200 : 503,
    retryAfterSeconds: queue.retryAfterSeconds,
    body: busyResponse(body, text, queue.retryAfterSeconds, apps),
  }
}
