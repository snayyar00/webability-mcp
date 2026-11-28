import type { IncomingHttpHeaders } from 'node:http'
import { contrastLaunchesBrowser } from './contrastPalette.js'
import { ACCOUNT_TOOLS, signInSteps } from './signIn.js'

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
  const policy = clientIpPolicy(env)
  if (policy.source === 'cf-connecting-ip') {
    const cf = String(headers['cf-connecting-ip'] || '').trim()
    if (cf) return cf
  }
  if (policy.source === 'x-forwarded-for') {
    const raw = headers['x-forwarded-for']
    const entries = (Array.isArray(raw) ? raw.join(',') : String(raw || ''))
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    if (entries.length >= policy.hops) return entries[entries.length - policy.hops]
  }
  return socket

}

type ClientIpPolicy =
  | { source: 'cf-connecting-ip' }
  | { source: 'socket' }
  | { source: 'x-forwarded-for'; hops: number }

/**
 * The env-var decision behind `clientIp`, parsed once so the boot log and the
 * lookup cannot disagree. TRUSTED_PROXY_HOPS defaults to 1 and falls back to 1
 * for unparsable or negative values; 0 means no proxy.
 */
function clientIpPolicy(env: NodeJS.ProcessEnv): ClientIpPolicy {
  if ((env.TRUST_CF_CONNECTING_IP || '').trim().toLowerCase() === 'true') return { source: 'cf-connecting-ip' }
  const parsed = Number.parseInt(String(env.TRUSTED_PROXY_HOPS ?? '1'), 10)
  const hops = Number.isFinite(parsed) && parsed >= 0 ? parsed : 1
  return hops === 0 ? { source: 'socket' } : { source: 'x-forwarded-for', hops }
}

/**
 * One line, logged at boot, naming the source `clientIp` will key the
 * anonymous limiter on. Both env vars fail silently when wrong, so the
 * effective policy is stated rather than assumed.
 */
export function describeClientIpPolicy(env: NodeJS.ProcessEnv = process.env): string {
  const policy = clientIpPolicy(env)
  if (policy.source === 'cf-connecting-ip') return 'CF-Connecting-IP (TRUST_CF_CONNECTING_IP=true; the origin must accept Cloudflare traffic alone)'
  if (policy.source === 'socket') return 'the socket address (TRUSTED_PROXY_HOPS=0)'
  const { hops } = policy
  return `the rightmost ${hops} entr${hops === 1 ? 'y' : 'ies'} of X-Forwarded-For (TRUSTED_PROXY_HOPS=${hops}), falling back to the socket address`
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

/** One anonymous AI-fix unit is 16 KB of relayed payload. */
const AI_WEIGHT_UNIT_BYTES = 16 * 1024

function argBytes(v: unknown): number {
  if (v === undefined || v === null) return 0
  if (typeof v === 'string') return Buffer.byteLength(v, 'utf8')
  try {
    return Buffer.byteLength(JSON.stringify(v) ?? '', 'utf8')
  } catch {
    return 0
  }
}

/**
 * What one anonymous call costs its per-IP bucket. AI fixes are relayed to a
 * metered model with the caller's own payload, so the charge is that payload's
 * weight — one unit per 16 KB, rounded up — not a flat one: a flat count let a
 * single 2 MB call buy a whole hour's budget. Every other tool costs one.
 */
export function anonCallCost(call: ToolCall): number {
  if (anonLimitClass(call) !== 'ai') return 1
  const a = (call.args ?? {}) as Record<string, unknown>
  const bytes = argBytes(a.html) + argBytes(a.context) + argBytes(a.issue)
  return Math.max(1, Math.ceil(bytes / AI_WEIGHT_UNIT_BYTES))
}

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
    allow(key: string, limit: number, cost = 1): AnonGateResult {
      const t = now()
      let b = buckets.get(key)
      if (!b || b.resetAt <= t) {
        b = { n: 0, resetAt: t + WINDOW_MS }
        buckets.set(key, b)
        if (buckets.size > 50_000) {
          for (const [k, v] of buckets) if (v.resetAt <= t) buckets.delete(k)
        }
      }
      // Charge what the request tried to spend, refused or not: otherwise a
      // caller retries a refused heavy call for free until the window closes.
      b.n += cost
      return { ok: b.n <= limit, retryAfterS: Math.max(0, Math.ceil((b.resetAt - t) / 1000)), resetAt: b.resetAt }
    },
    /** Would the NEXT allow() for this key be refused? Counts nothing. */
    full(key: string, limit: number): AnonGateResult {
      const t = now()
      const b = buckets.get(key)
      if (!b || b.resetAt <= t) return { ok: true, retryAfterS: 0, resetAt: t + WINDOW_MS }
      return { ok: b.n < limit, retryAfterS: Math.max(0, Math.ceil((b.resetAt - t) / 1000)), resetAt: b.resetAt }
    },
  }
}

function limitParts(o: { cls: 'heavy' | 'ai' | 'account'; limit: number; retryAfterS: number; resetAt: number }) {
  const what =
    o.cls === 'ai'
      ? o.limit === 1
        ? 'AI fix call'
        : 'AI fix calls'
      : o.cls === 'account'
        ? o.limit === 1
          ? 'account call'
          : 'account calls'
        : o.limit === 1
          ? 'page-loading call'
          : 'page-loading calls'
  const wait = o.retryAfterS < 60 ? `${o.retryAfterS} s` : `${Math.ceil(o.retryAfterS / 60)} min`
  const at = new Date(o.resetAt).toISOString().slice(11, 16)
  return { what, wait, at }
}

/**
 * Which per-IP operator bucket a tool call counts against, or null.
 *
 * A caller holding the shared MCP_AUTH_TOKEN is not anonymous — the anonymous
 * gate above skips it — and not identified — no account token, so account
 * tools run against the deploy's own API key. The harm is spend and side
 * effects on our account, which is the ACCOUNT_TOOLS family plus the heavy and
 * AI families; this gives each of them a budget (#227).
 */
export function operatorLimitClass(call: ToolCall): 'heavy' | 'ai' | 'account' | null {
  const cls = anonLimitClass(call)
  if (cls) return cls
  if (ACCOUNT_TOOLS.has(call.name)) return 'account'
  return null
}

/**
 * The operator-cap answer. Deliberately not the anonymous message: this caller
 * already has a credential, so "sign in with a free account" is not the fix —
 * the fix is a per-user token, and the env var names what to raise.
 */
export function operatorLimitMessage(o: { cls: 'heavy' | 'ai' | 'account'; limit: number; retryAfterS: number; resetAt: number }): string {
  const { what, wait, at } = limitParts(o)
  const envVar = o.cls === 'ai' ? 'OPERATOR_AI_PER_HOUR' : o.cls === 'account' ? 'OPERATOR_ACCOUNT_PER_HOUR' : 'OPERATOR_HEAVY_PER_HOUR'
  return (
    `Operator token limit reached: ${o.limit} ${what} per hour from this IP address (${envVar}). Nothing ran. ` +
    `It resets in ${wait} (at ${at} UTC). ` +
    'Use a WebAbility user token instead of the shared operator token so calls are attributed to an account: ' +
    signInSteps().join(' ')
  )
}

/**
 * The anonymous-cap answer on /mcp/apps (ChatGPT): the limit and reset time,
 * no other client's sign-in steps. ChatGPT shows its sign-in button from the
 * challenge the caller puts next to this text.
 */
export function appsAnonLimitMessage(o: { cls: 'heavy' | 'ai'; limit: number; retryAfterS: number; resetAt: number }): string {
  const { what, wait, at } = limitParts(o)
  return (
    `Anonymous fair-use limit reached: ${o.limit} ${what} per hour from this network. Nothing ran. ` +
    `It resets in ${wait} (at ${at} UTC). Sign in to WebAbility when ChatGPT asks to keep going now.`
  )
}

/**
 * The anonymous-cap answer. Persona round 4: the old text ("… or retry
 * later") gave no limit and no reset time. States the limit, when this
 * caller's window resets, and how to remove the limit.
 */
export function anonLimitMessage(o: { cls: 'heavy' | 'ai'; limit: number; retryAfterS: number; resetAt: number }): string {
  const { what, wait, at } = limitParts(o)
  const examples = o.cls === 'ai' ? ` (${[...AI_TOOLS].join(', ')})` : ` (${[...HEAVY_TOOLS].join(', ')}, check_color_contrast with a url + selector or with a url and no brandColors)`
  return (
    `Anonymous fair-use limit reached: ${o.limit} ${what}${examples} per hour from this IP address. ` +
    `It resets in ${wait} (at ${at} UTC). ` +
    'Sign in with a free WebAbility account to remove the limit:\n' +
    signInSteps().join('\n') +
    '\nDocs: https://www.webability.io/docs/mcp'
  )
}
