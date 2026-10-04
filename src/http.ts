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
 * AUTH IS PER-USER. Everything is free. Anonymous callers get the scan/check
 * tools under per-IP fair-use limits; signing in with a free WebAbility account
 * unlocks visual_audit / start_audit / get_audit. Each caller sends THEIR OWN
 * WebAbility token as `Authorization: Bearer <token>` (or, when
 * fronted by a gateway that reserves Authorization, as `x-webability-token`). It
 * is validated against the API and then used for that caller's account-tool calls,
 * so an audit belongs to the caller's account. This is what lets a directory like
 * Smithery pass each user's key straight through (no shared secret to leak).
 *
 * Backward-compat: a shared MCP_AUTH_TOKEN, when set, is still accepted
 * (operator mode → account tools fall back to the deploy's WEBABILITY_API_KEY).
 */
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'http'
import { timingSafeEqual } from 'crypto'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createServer } from './server.js'
import { handleOAuth, wwwAuthenticate } from './oauth.js'
import { anonLimitClass, calledTools, clientIp } from './anonGate.js'

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
// scan/check tools anonymously. Everything is free; fair-use limits apply.
// The account tools (start_audit/get_audit/visual_audit) need a free
// WebAbility account: an anonymous call gets 401 + WWW-Authenticate, which
// spec clients answer by running the OAuth flow in oauth.ts on demand.
// Anonymous traffic launches OUR browsers and calls OUR AI endpoint, so the
// scan/check tools are rate-limited per client IP — in-memory counters only
// (single-container deploy), never per-request writes to paid storage.
// ---------------------------------------------------------------------------
// Checked BEFORE dispatch (not inside the tool handler): only a pre-dispatch
// check can return a real HTTP 401 + WWW-Authenticate — inside the MCP
// JSON-RPC tool call any outcome is a 200 "tool result", so a spec client
// could never auto-trigger its OAuth flow. It also means visual_audit never
// launches a headless browser for a call that was always going to be refused.
const ACCOUNT_TOOLS = new Set(['start_audit', 'get_audit', 'visual_audit'])
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

  // OpenAI apps directory domain verification. Public token from the portal;
  // 404 when unset. Never logged.
  if (url.pathname === '/.well-known/openai-apps-challenge' && req.method === 'GET') {
    const challenge = process.env.OPENAI_APPS_CHALLENGE_TOKEN?.trim()
    if (!challenge) {
      sendJson(res, 404, { error: 'not_found' })
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(challenge)
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
  // token lifts the limits and unlocks the account tools, which run on that
  // caller's account. A GARBAGE token is still a hard 401 (a caller who tried
  // to authenticate should learn their token is bad, not be silently
  // downgraded to anonymous). The shared operator token is accepted too.
  const token = bearer(req)
  let authToken: string | undefined
  let anonymous = false
  if (!token) {
    anonymous = true
  } else if (matchesShared(token)) {
    authToken = undefined // operator mode: account tools use the deploy's WEBABILITY_API_KEY
  } else if (await isValidUserToken(token)) {
    authToken = token // per-user mode: account tools use the caller's key
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

    const ip = clientIp(req.headers, req.socket.remoteAddress)

    if (anonymous) {
      // Every tool the body calls — a JSON-RPC batch must not slip past the
      // gate by hiding its calls in an array (see anonGate.ts).
      const tools = calledTools(body)
      const needsAccount = tools.map((t) => t.name).find((n) => ACCOUNT_TOOLS.has(n))
      if (needsAccount) {
        res.setHeader('WWW-Authenticate', wwwAuthenticate())
        sendJson(res, 401, {
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message:
              `${needsAccount} needs a free WebAbility account. Sign in when your client prompts you (OAuth), or run \`webability login\`. ` +
              'The scanning tools work without an account.',
          },
          id: null,
        })
        return
      }
      for (const tool of tools) {
        const cls = anonLimitClass(tool)
        if (!cls) continue
        const gate = allowAnon(`${ip}:${cls}`, cls === 'ai' ? ANON_AI_PER_HOUR : ANON_HEAVY_PER_HOUR)
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

    const server = createServer({ remote: true, authToken, anonymous })
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
