import type { IncomingHttpHeaders } from 'node:http'
import { contrastLaunchesBrowser } from './contrastPalette.js'
import { signInSteps } from './signIn.js'

/**
 * The address the hosted anonymous rate limit keys on. It must be one
 * the caller cannot choose.
 *
 * X-Forwarded-For is "<whatever the client sent>, <hop 1 saw>, <hop 2 saw>":
 * each proxy APPENDS the peer it saw, so only the rightmost TRUSTED_PROXY_HOPS
 * entries were written by our own infrastructure. Reading the leftmost entry
 * (the old behaviour) let a caller mint a fresh bucket per request.
 *
 * - TRUST_CF_CONNECTING_IP=true: use CF-Connecting-IP (Cloudflare sets it and
 *   overwrites any client copy). Only safe when the origin accepts Cloudflare
 *   traffic alone.
 * - TRUSTED_PROXY_HOPS (default 1): the number of our proxies in front of this
 *   process. 1 = Traefik only; 2 = Cloudflare -> Traefik; 0 = no proxy, use the
 *   socket.
 */
export function clientIp(
  headers: IncomingHttpHeaders,
  remoteAddress: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const socket = (remoteAddress || 'unknown').trim()
  if ((env.TRUST_CF_CONNECTING_IP || '').trim().toLowerCase() === 'true') {
    const cf = String(headers['cf-connecting-ip'] || '').trim()
    if (cf) return cf
  }
  const parsed = Number.parseInt(String(env.TRUSTED_PROXY_HOPS ?? '1'), 10)
  const hops = Number.isFinite(parsed) && parsed >= 0 ? parsed : 1
  if (hops === 0) return socket
  const raw = headers['x-forwarded-for']
  const entries = (Array.isArray(raw) ? raw.join(',') : String(raw || ''))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (entries.length < hops) return socket
  return entries[entries.length - hops]
}

export interface ToolCall {
  name: string
  args?: unknown
}

/** Every tool a request body calls, with its arguments — a single JSON-RPC message or a batch. */
export function calledTools(body: unknown): ToolCall[] {
  const messages = Array.isArray(body) ? body : [body]
  const calls: ToolCall[] = []
  for (const m of messages as any[]) {
    if (m && m.method === 'tools/call' && m.params && typeof m.params.name === 'string') {
      calls.push({ name: m.params.name, args: m.params.arguments })
    }
  }
  return calls
}

// Browser-launching tools: each call is a headless page on this box.
const HEAVY_TOOLS = new Set(['scan_page', 'flow_scan', 'diff_scan', 'verify_fix', 'detect_framework', 'scan_html', 'check_aria'])
const AI_TOOLS = new Set(['generate_ai_fix'])

/**
 * Which per-IP anonymous bucket a tool call counts against, or null for none.
 * check_color_contrast is pure color math unless it is given a url, which it
 * loads in Chromium — so its class depends on the arguments.
 */
export function anonLimitClass(call: ToolCall): 'heavy' | 'ai' | null {
  if (AI_TOOLS.has(call.name)) return 'ai'
  if (HEAVY_TOOLS.has(call.name)) return 'heavy'
  // check_color_contrast loads `url` in Chromium only when brandColors parses
  // to an empty palette. The handler calls the same contrastLaunchesBrowser
  // test, so a call that reaches Chromium is always heavy. (It may still skip
  // the browser when the pair passes AA; counting that case is the safe side.)
  if (call.name === 'check_color_contrast' && contrastLaunchesBrowser(call.args)) return 'heavy'
  return null
}

const WINDOW_MS = 60 * 60 * 1000

export type AnonGateResult = { ok: boolean; retryAfterS: number; resetAt: number }

/**
 * Per-key fixed-window counters (one hour, opened by the key's first call).
 * In-memory only — single-container deploy, never per-request writes to
 * paid storage. `resetAt` is the window's own end, so the 429 can say when
 * it resets.
 */
export function createAnonLimiter(now: () => number = Date.now) {
  const buckets = new Map<string, { n: number; resetAt: number }>()
  return {
    allow(key: string, limit: number): AnonGateResult {
      const t = now()
      let b = buckets.get(key)
      if (!b || b.resetAt <= t) {
        b = { n: 0, resetAt: t + WINDOW_MS }
        buckets.set(key, b)
        if (buckets.size > 50_000) {
          for (const [k, v] of buckets) if (v.resetAt <= t) buckets.delete(k)
        }
      }
      b.n += 1
      return { ok: b.n <= limit, retryAfterS: Math.max(0, Math.ceil((b.resetAt - t) / 1000)), resetAt: b.resetAt }
    },
  }
}

/**
 * The anonymous-cap answer. Persona round 4: the old text ("… or retry
 * later") gave no limit and no reset time. States the limit, when this
 * caller's window resets, and how to remove the limit.
 */
export function anonLimitMessage(o: { cls: 'heavy' | 'ai'; limit: number; retryAfterS: number; resetAt: number }): string {
  const what = o.cls === 'ai' ? (o.limit === 1 ? 'AI fix call' : 'AI fix calls') : o.limit === 1 ? 'page-loading call' : 'page-loading calls'
  const examples = o.cls === 'ai' ? ` (${[...AI_TOOLS].join(', ')})` : ` (${[...HEAVY_TOOLS].join(', ')}, check_color_contrast with a url + selector or with a url and no brandColors)`
  const wait = o.retryAfterS < 60 ? `${o.retryAfterS} s` : `${Math.ceil(o.retryAfterS / 60)} min`
  const at = new Date(o.resetAt).toISOString().slice(11, 16)
  return (
    `Anonymous fair-use limit reached: ${o.limit} ${what}${examples} per hour from this IP address. ` +
    `It resets in ${wait} (at ${at} UTC). ` +
    'Sign in with a free WebAbility account to remove the limit:\n' +
    signInSteps().join('\n') +
    '\nDocs: https://www.webability.io/docs/mcp'
  )
}
