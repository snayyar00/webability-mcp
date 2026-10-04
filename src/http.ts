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
import { anonLimitClass, anonLimitMessage, calledTools, clientIp, createAnonLimiter } from './anonGate.js'
import { MCP_PATH, PUBLIC_URL, SIGN_IN_MCP_PATH } from './signIn.js'

const PORT = Number(process.env.PORT || 8080)
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

/**
 * Validate a caller's WebAbility token against the API (cached).
 * Only 401/403 from the API are a verdict on the token ('invalid').
 * 'unavailable' = no verdict: network error, 5xx, throttling (429) or another
 * transient status (408, 425, ...). That is not a
 * verdict on the token: answering it with 401 would make Claude Code mark the
 * server needs-auth (zero tools in later sessions) and claude.ai invalidate
 * the connector, for every signed-in user, during an API outage.
 */
type TokenCheck = { state: 'valid' | 'invalid' } | { state: 'unavailable'; retryAfter: string }
const DEFAULT_RETRY_AFTER_S = '30'

/** Upstream Retry-After when it is delta-seconds or an HTTP date; otherwise our default. */
function retryAfterFrom(res: Response): string {
  const raw = (res.headers.get('retry-after') || '').trim()
  if (/^\d{1,6}$/.test(raw)) return raw
  const when = Date.parse(raw)
  if (!Number.isNaN(when)) return String(Math.max(1, Math.ceil((when - Date.now()) / 1000)))
  return DEFAULT_RETRY_AFTER_S
}

async function checkUserToken(token: string): Promise<TokenCheck> {
  if (!token) return { state: 'invalid' }
  const cached = tokenCache.get(token)
  if (cached && cached > Date.now()) return { state: 'valid' }
  try {
    const res = await fetch(`${API_URL}/cli/whoami`, { headers: { Authorization: `Bearer ${token}` } })
    if (res.ok) {
      tokenCache.set(token, Date.now() + TOKEN_TTL_MS)
      return { state: 'valid' }
    }
    if (res.status === 401 || res.status === 403) return { state: 'invalid' }
    return { state: 'unavailable', retryAfter: retryAfterFrom(res) }
  } catch {
    return { state: 'unavailable', retryAfter: DEFAULT_RETRY_AFTER_S }
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

// ---------------------------------------------------------------------------
// Partial auth on /mcp: anyone can list and call the scan/check tools
// anonymously. Everything is free; fair-use limits apply. The account tools
// (start_audit/get_audit/visual_audit) need a free WebAbility account. An
// anonymous call to one gets a normal tool result with isError and the
// sign-in steps (server.ts, signIn.ts) — NOT an HTTP 401: a 401 on a tool call
// makes Claude Code cache the server as needs-auth, and every later session
// then lists zero tools. Clients that start OAuth only on a 401 use
// /mcp/auth, which challenges every request without a valid token.
// Anonymous traffic launches OUR browsers and calls OUR AI endpoint, so the
// scan/check tools are rate-limited per client IP — in-memory counters only
// (single-container deploy), never per-request writes to paid storage.
// ---------------------------------------------------------------------------
const ANON_HEAVY_PER_HOUR = Number(process.env.ANON_HEAVY_PER_HOUR || 30)
const ANON_AI_PER_HOUR = Number(process.env.ANON_AI_PER_HOUR || 10)

const anonLimiter = createAnonLimiter()

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

  if (url.pathname !== MCP_PATH && url.pathname !== SIGN_IN_MCP_PATH) {
    sendJson(res, 404, { error: 'not_found' })
    return
  }
  const mcpPath = url.pathname

  // Auth is PARTIAL on /mcp. Anyone can initialize, list tools, and call the
  // free (DOM/scanner) tools anonymously — rate-limited per IP. A valid
  // per-user token lifts the limits and unlocks the account tools, which run
  // on that caller's account. /mcp/auth has no anonymous mode: a request
  // without a token gets 401 + WWW-Authenticate so the client signs in. A
  // GARBAGE token is a hard 401 on both paths (a caller who tried to
  // authenticate should learn their token is bad, not be silently downgraded
  // to anonymous; the MCP spec requires 401 for an invalid token). The shared
  // operator token is accepted too.
  const token = bearer(req)
  let authToken: string | undefined
  let anonymous = false
  let tokenCheck: TokenCheck = { state: 'invalid' }
  if (!token && mcpPath === SIGN_IN_MCP_PATH) {
    res.setHeader('WWW-Authenticate', wwwAuthenticate(mcpPath))
    sendJson(res, 401, {
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message:
          'This URL is the sign-in path: sign in with a free WebAbility account when your client asks. ' +
          `The scan and check tools also work without an account at ${PUBLIC_URL}${MCP_PATH}. Docs: https://www.webability.io/docs/mcp`,
      },
      id: null,
    })
    return
  } else if (!token) {
    anonymous = true
  } else if (matchesShared(token)) {
    authToken = undefined // operator mode: account tools use the deploy's WEBABILITY_API_KEY
  } else if ((tokenCheck = await checkUserToken(token)).state === 'valid') {
    authToken = token // per-user mode: account tools use the caller's key
  } else if (tokenCheck.state === 'unavailable') {
    res.setHeader('Retry-After', tokenCheck.retryAfter)
    sendJson(res, 503, {
      jsonrpc: '2.0',
      error: { code: -32603, message: 'WebAbility could not check your sign-in right now (the account service did not answer). Retry in a minute; your sign-in is still valid.' },
      id: null,
    })
    return
  } else {
    res.setHeader('WWW-Authenticate', wwwAuthenticate(mcpPath))
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
      // Account tools are not refused here: their handlers return an isError
      // tool result before any browser or API work (server.ts).
      const tools = calledTools(body)
      for (const tool of tools) {
        const cls = anonLimitClass(tool)
        if (!cls) continue
        const limit = cls === 'ai' ? ANON_AI_PER_HOUR : ANON_HEAVY_PER_HOUR
        const gate = anonLimiter.allow(`${ip}:${cls}`, limit)
        if (!gate.ok) {
          res.setHeader('Retry-After', String(gate.retryAfterS))
          sendJson(res, 429, {
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: anonLimitMessage({ cls, limit, retryAfterS: gate.retryAfterS, resetAt: gate.resetAt }),
              data: { limit, perHours: 1, retryAfterSeconds: gate.retryAfterS, resetAt: new Date(gate.resetAt).toISOString() },
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
