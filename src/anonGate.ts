import type { IncomingHttpHeaders } from 'node:http'
import { contrastLaunchesBrowser } from './contrastPalette.js'

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
