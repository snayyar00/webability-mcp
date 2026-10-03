#!/usr/bin/env node
/**
 * Remote (Streamable HTTP) transport for the WebAbility MCP server.
 *
 * The default entry (index.ts) speaks stdio — for Claude Code / Cursor.
 * This entry exposes the SAME tools over HTTP so the server can be hosted and
 * added as a remote MCP server (Smithery, a Lovable "chat connector", etc. —
 * they accept a remote URL + auth, never a local stdio/npx process).
 *
 * Stateless mode: a fresh server + transport per request, so concurrent clients
 * never share request state.
 *
 * AUTH IS PER-USER. The hosted endpoint runs on our infra and launches browsers,
 * so it never runs anonymously — but instead of one shared secret, each caller
 * sends THEIR OWN WebAbility token as `Authorization: Bearer <token>` (or, when
 * fronted by a gateway that reserves Authorization, as `x-webability-token`). It
 * is validated against the API and then used for that caller's paid-tool calls,
 * so an audit bills to the caller's account. This is what lets a directory like
 * Smithery pass each user's key straight through (no shared secret to leak).
 *
 * Backward-compat: a shared MCP_AUTH_TOKEN, when set, is still accepted
 * (operator mode → paid tools fall back to the deploy's WEBABILITY_API_KEY).
 */
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'http'
import { timingSafeEqual, createHmac } from 'crypto'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createServer } from './server.js'
import { handleOAuth, wwwAuthenticate } from './oauth.js'

const PORT = Number(process.env.PORT || 8080)
const MCP_PATH = '/mcp'
const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

// Optional shared operator token (backward-compat). A per-user token is the
// normal path, so this is no longer required for the server to start.
const SHARED_TOKEN = process.env.MCP_AUTH_TOKEN && process.env.MCP_AUTH_TOKEN.length >= 32 ? process.env.MCP_AUTH_TOKEN : ''

// Validated-token cache: token → expiry epoch ms. Avoids a /cli/whoami round-trip
// on every request in the stateless model; short TTL so revocation propagates.
const tokenCache = new Map<string, number>()
const TOKEN_TTL_MS = 5 * 60 * 1000

function bearer(req: IncomingMessage): string {
  // Prefer the standard Authorization header (direct clients, the CLI, the
  // operator token). Fall back to x-webability-token: gateways like Smithery
  // reserve Authorization for their own hop and refuse to forward it upstream,
  // so they carry the user's token in a non-reserved custom header instead.
  const raw = (req.headers['x-webability-token'] as string) || req.headers.authorization || ''
  return raw.replace(/^Bearer\s+/i, '').trim()
}

/** Constant-time match for the shared operator token (no length/prefix timing leak). */
function matchesShared(token: string): boolean {
  if (!SHARED_TOKEN || !token) return false
  const a = Buffer.from(token)
  const b = Buffer.from(SHARED_TOKEN)
  return a.length === b.length && timingSafeEqual(a, b)
}

/** Validate a caller's WebAbility token against the API (cached). */
async function isValidUserToken(token: string): Promise<boolean> {
  if (!token) return false
  const cached = tokenCache.get(token)
  if (cached && cached > Date.now()) return true
  try {
    const res = await fetch(`${API_URL}/cli/whoami`, { headers: { Authorization: `Bearer ${token}` } })
    if (res.ok) {
      tokenCache.set(token, Date.now() + TOKEN_TTL_MS)
      return true
    }
  } catch {
    // network error reaching the API — treat as unauthorized for this request
  }
  return false
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

// ---------------------------------------------------------------------------
// Partial auth: the server starts AUTHLESS so anyone can list and call the
// free tools. The paid tools (start_audit/get_audit/visual_audit) get a
// TRIAL instead of an immediate 401 — MCP_TRIAL_LIMIT calls (default 50) per
// anonymous IP, tracked durably by the platform API (see cli.routes.ts
// /cli/mcp-trial/*) so it survives a container restart. Once the trial is
// spent, those tools 401 + WWW-Authenticate, which spec clients answer by
// running the OAuth flow in oauth.ts on demand. Anonymous traffic launches
// OUR browsers and calls OUR AI endpoint, so the free (non-trial) tools are
// separately rate-limited per client IP — never per-request writes to paid
// storage, just in-memory counters (single-container deploy).
// ---------------------------------------------------------------------------
// Server-to-server secret shared with the platform API's /cli/mcp-trial/*
// routes — never sent to, or derivable by, an end client.
const MCP_TRIAL_INTERNAL_SECRET = process.env.MCP_TRIAL_INTERNAL_SECRET || ''
// HMAC key for turning a caller's IP into an opaque trial-bucket id before it
// ever leaves this process. Held only here; the API just stores the digest.
const MCP_TRIAL_IP_SECRET = process.env.MCP_TRIAL_IP_SECRET || ''
function trialIpKeyFor(ip: string): string {
  if (!MCP_TRIAL_INTERNAL_SECRET || !MCP_TRIAL_IP_SECRET) return ''
  return createHmac('sha256', MCP_TRIAL_IP_SECRET).update(ip).digest('hex')
}
// The three tools trial credits gate. Checked BEFORE dispatch (not inside
// the tool handler) for two reasons: (1) only a pre-dispatch check can
// return a real HTTP 401 + WWW-Authenticate — once we're inside the MCP
// JSON-RPC tool call, any outcome is a 200 "tool result", so a spec client
// can never auto-trigger its OAuth flow on exhaustion; (2) visual_audit
// launches a real headless browser as its first action — checking only
// inside that handler (as the actual credit debit still does, server-side)
// would let an already-exhausted anonymous caller keep paying for browser
// launches indefinitely, since every one of those calls was always going to
// 429 anyway.
const PAID_TOOLS = new Set(['start_audit', 'get_audit', 'visual_audit'])
/** Read-only: how many trial calls remain, WITHOUT spending one (the actual
 *  debit happens later, inside the real start_audit/get_audit/visual_audit
 *  backend call in server.ts). Never throws — a network hiccup here just
 *  means we fail closed (treat as exhausted) rather than crash the request. */
async function peekTrialRemaining(trialIpKey: string): Promise<number> {
  if (!trialIpKey) return 0
  try {
    const res = await fetch(`${API_URL}/cli/mcp-trial/status`, {
      headers: { 'x-mcp-internal': MCP_TRIAL_INTERNAL_SECRET, 'x-mcp-trial-ip': trialIpKey },
    })
    if (!res.ok) return 0
    const data = (await res.json()) as { remaining?: number }
    return typeof data.remaining === 'number' ? data.remaining : 0
  } catch {
    return 0
  }
}
// Browser-launching tools: each call is a headless page on this box.
const HEAVY_TOOLS = new Set(['scan_page', 'flow_scan', 'diff_scan', 'verify_fix', 'detect_framework', 'scan_html', 'check_aria'])
const AI_TOOLS = new Set(['generate_ai_fix'])
const ANON_HEAVY_PER_HOUR = Number(process.env.ANON_HEAVY_PER_HOUR || 30)
const ANON_AI_PER_HOUR = Number(process.env.ANON_AI_PER_HOUR || 10)

const anonBuckets = new Map<string, { n: number; resetAt: number }>()
function allowAnon(key: string, limit: number): { ok: boolean; retryAfterS: number } {
  const now = Date.now()
  let b = anonBuckets.get(key)
  if (!b || b.resetAt < now) {
    b = { n: 0, resetAt: now + 60 * 60 * 1000 }
    anonBuckets.set(key, b)
    if (anonBuckets.size > 50_000) {
      for (const [k, v] of anonBuckets) if (v.resetAt < now) anonBuckets.delete(k)
    }
  }
  b.n += 1
  return { ok: b.n <= limit, retryAfterS: Math.ceil((b.resetAt - now) / 1000) }
}

// Only trust CF-Connecting-IP when the operator declares the origin sits behind
// Cloudflare (TRUST_CF_CONNECTING_IP=true). On a Cloudflare-fronted deployment
// that header is set by Cloudflare to the real visitor and overwrites any client
// copy, so it is trustworthy AND unspoofable — provided the origin only accepts
// Cloudflare traffic. Defaulting this OFF keeps non-Cloudflare deployments (a
// bare `node dist/http.js`, or a proxy that overwrites X-Forwarded-For) on their
// existing, trustworthy XFF/socket chain: trusting CF-Connecting-IP there would
// let a client forge a header the old code never read, reintroducing the bypass.
const TRUST_CF_CONNECTING_IP =
  (process.env.TRUST_CF_CONNECTING_IP || '').trim().toLowerCase() === 'true'

function clientIp(req: IncomingMessage): string {
  // The leftmost X-Forwarded-For entry is client-controlled: a caller can send
  // `X-Forwarded-For: <random>` on every request to mint a fresh rate-limit
  // bucket and bypass allowAnon. Prefer the Cloudflare-set header when the
  // operator has opted in; otherwise fall back to the XFF/socket chain.
  if (TRUST_CF_CONNECTING_IP) {
    const cf = (req.headers['cf-connecting-ip'] as string) || ''
    if (cf.trim()) return cf.trim()
  }
  const fwd = (req.headers['x-forwarded-for'] as string) || ''
  return (fwd.split(',')[0] || req.socket.remoteAddress || 'unknown').trim()
}

function calledTool(body: unknown): string {
  const b = body as any
  return b && b.method === 'tools/call' && b.params && typeof b.params.name === 'string' ? b.params.name : ''
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  if (chunks.length === 0) return undefined
  const raw = Buffer.concat(chunks).toString('utf8')
  return raw ? JSON.parse(raw) : undefined
}

const httpServer = createHttpServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)

  // CORS preflight — remote clients connect server-side, but stay permissive + safe.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-webability-token, Mcp-Session-Id, Mcp-Protocol-Version',
    })
    res.end()
    return
  }

  // OAuth front door (metadata, DCR, authorize, token) — see oauth.ts.
  try {
    if (await handleOAuth(req, res, url)) return
  } catch (err) {
    console.error('[oauth] request error:', err)
    if (!res.headersSent) sendJson(res, 500, { error: 'server_error' })
    return
  }

  if (url.pathname === '/health') {
    sendJson(res, 200, { ok: true, service: 'webability-mcp', transport: 'streamable-http' })
    return
  }

  // Humans who open the bare domain (e.g. from the dashboard card) get sent to
  // the setup docs — only /mcp (machines) and /health live here.
  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(302, { Location: 'https://www.webability.io/docs/mcp' })
    res.end()
    return
  }

  if (url.pathname !== MCP_PATH) {
    sendJson(res, 404, { error: 'not_found' })
    return
  }

  // Auth is PARTIAL. Anyone can initialize, list tools, and call the free
  // (DOM/scanner) tools anonymously — rate-limited per IP. A valid per-user
  // token lifts the limits and unlocks the paid tools, which bill to that
  // caller's account. A GARBAGE token is still a hard 401 (a caller who tried
  // to authenticate should learn their token is bad, not be silently
  // downgraded to anonymous). The shared operator token is accepted too.
  const token = bearer(req)
  let authToken: string | undefined
  let anonymous = false
  if (!token) {
    anonymous = true
  } else if (matchesShared(token)) {
    authToken = undefined // operator mode: paid tools use the deploy's WEBABILITY_API_KEY
  } else if (await isValidUserToken(token)) {
    authToken = token // per-user mode: paid tools use the caller's key
  } else {
    res.setHeader('WWW-Authenticate', wwwAuthenticate())
    sendJson(res, 401, {
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message:
          'Invalid or expired token. Reconnect (your client re-runs the sign-in), run `webability login` for a fresh token, ' +
          'or drop the Authorization header entirely — the free scanning tools work without an account. ' +
          'Docs: https://www.webability.io/docs/mcp',
      },
      id: null,
    })
    return
  }

  try {
    const body = req.method === 'POST' ? await readJsonBody(req) : undefined

    const trialIpKey = anonymous ? trialIpKeyFor(clientIp(req)) : ''

    if (anonymous) {
      const tool = calledTool(body)
      if (PAID_TOOLS.has(tool)) {
        // Pre-dispatch trial gate: a PEEK (never spends a credit — the real
        // debit happens inside server.ts's start_audit/get_audit/visual_audit
        // handler, as part of the actual paid call). Checked here, before the
        // tool ever runs, so an exhausted caller gets a real 401 +
        // WWW-Authenticate (spec clients auto-run OAuth on that) instead of a
        // 200 JSON-RPC "tool result" saying no — and so visual_audit's
        // headless-browser launch never happens for a call that was always
        // going to be refused.
        const remaining = await peekTrialRemaining(trialIpKey)
        if (remaining <= 0) {
          res.setHeader('WWW-Authenticate', wwwAuthenticate())
          sendJson(res, 401, {
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message:
                `${tool} runs paid server-side work. The free trial is used up (or not available right now). ` +
                'Authorize this connector when your client prompts you to sign in (free account works), or run `webability login`. ' +
                'The scanning tools keep working without an account.',
            },
            id: null,
          })
          return
        }
      }
      const limit = AI_TOOLS.has(tool) ? ANON_AI_PER_HOUR : HEAVY_TOOLS.has(tool) ? ANON_HEAVY_PER_HOUR : 0
      if (limit > 0) {
        const gate = allowAnon(`${clientIp(req)}:${AI_TOOLS.has(tool) ? 'ai' : 'heavy'}`, limit)
        if (!gate.ok) {
          res.setHeader('Retry-After', String(gate.retryAfterS))
          sendJson(res, 429, {
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: 'Anonymous rate limit reached for this tool. Sign in with a free WebAbility account to continue without limits, or retry later.',
            },
            id: null,
          })
          return
        }
      }
    }

    const server = createServer({ remote: true, authToken, anonymous, trialIpKey })
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
    res.on('close', () => {
      transport.close().catch(() => {})
      server.close().catch(() => {})
    })
    await server.connect(transport)
    await transport.handleRequest(req, res, body)
  } catch (err) {
    console.error('[mcp-http] request error:', err)
    if (!res.headersSent) {
      sendJson(res, 500, { jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null })
    }
  }
})

httpServer.listen(PORT, () => {
  console.error(`WebAbility MCP (Streamable HTTP) listening on :${PORT}${MCP_PATH}`)
})
