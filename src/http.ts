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
import { createHash, timingSafeEqual } from 'crypto'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createServer } from './server.js'
import { scanHtmlBusyRefusal } from './scanHtmlGate.js'
import { assertSigningSecret, handleOAuth, type OAuthHooks, wwwAuthenticate } from './oauth.js'
import { anonCallCost, anonLimitClass, anonLimitMessage, appsAnonLimitMessage, calledTools, clientIp, createAnonLimiter, describeClientIpPolicy, operatorLimitClass, operatorLimitMessage } from './anonGate.js'
import { APPS_MCP_PATH, MCP_PATH, MCP_PATHS, PUBLIC_URL, SIGN_IN_MCP_PATH, appsChallenge, resourceMetadataUrl } from './signIn.js'
import { SERVER_CARD_PATH, getServerCard } from './serverCard.js'
import { BodyTooLargeError, MCP_MAX_BODY_BYTES, declaredTooLarge, readBodyCapped } from './bodyLimit.js'
import { setSecurityHeaders } from './securityHeaders.js'
import { createTokenCache } from './tokenCache.js'

const PORT = Number(process.env.PORT || 8080)
const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

// Optional shared operator token (backward-compat). A per-user token is the
// normal path, so this is no longer required for the server to start.
const SHARED_TOKEN = process.env.MCP_AUTH_TOKEN && process.env.MCP_AUTH_TOKEN.length >= 32 ? process.env.MCP_AUTH_TOKEN : ''

// Validated-token cache: token → expiry epoch ms. Avoids a /cli/whoami round-trip
// on every request in the stateless model; short TTL so revocation propagates.
// Bounded, because every distinct token a caller sends would otherwise add an
// entry for the life of the process.
const tokenCache = createTokenCache({ max: 10_000 })
const TOKEN_TTL_MS = 5 * 60 * 1000

// scan_html's per-call budget, when an operator needs to lower it below the
// 24 s default (a smaller box, or a proxy with a shorter read timeout than the
// scan takes). Unset = fastScan's SCAN_HTML_DEADLINE_MS.
const scanHtmlDeadlineOverrideMs = Number(process.env.MCP_SCAN_HTML_DEADLINE_MS)

// Tokens the platform refused, by hash. A client retrying one dead token gets
// the same 401 without a platform call and without spending the IP's bad-token
// budget, so one expired token can never lock a network out. Same TTL as
// tokenCache, so a platform answer is never trusted for long.
const rejectedTokens = new Map<string, number>()
const REJECTED_TOKENS_MAX = 10_000

const tokenKey = (token: string) => createHash('sha256').update(token).digest('base64url')

function isRejected(token: string): boolean {
  const key = tokenKey(token)
  const exp = rejectedTokens.get(key)
  if (exp === undefined) return false
  if (exp > Date.now()) return true
  rejectedTokens.delete(key)
  return false
}

function rememberRejected(token: string): void {
  if (rejectedTokens.size >= REJECTED_TOKENS_MAX) {
    const oldest = rejectedTokens.keys().next().value
    if (oldest !== undefined) rejectedTokens.delete(oldest)
  }
  rejectedTokens.set(tokenKey(token), Date.now() + TOKEN_TTL_MS)
  tokenCache.delete(token)
}

/** A token the OAuth endpoints just got from the platform is known good. */
function rememberIssued(token: string): void {
  tokenCache.set(token, Date.now() + TOKEN_TTL_MS)
}

function bearerCandidates(req: IncomingMessage): string[] {
  // Authorization first (direct clients, OAuth, the CLI, the operator token).
  // x-webability-token is the fallback: gateways like Smithery reserve
  // Authorization for their own hop and refuse to forward it upstream, so they
  // carry the user's token in a custom header. A stale header pasted into a
  // client config must not override a live OAuth sign-in.
  const tokens = [req.headers.authorization, req.headers['x-webability-token']]
    .map((raw) => String(raw || '').replace(/^Bearer\s+/i, '').trim())
    .filter(Boolean)
  return [...new Set(tokens)]
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
  if (cached !== undefined) return { state: 'valid' }
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
// anonymous call to one gets a normal tool result (not isError) with the
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

/** /mcp/apps over the anonymous cap: a JSON-RPC response for each request in
 * the body (a batch stays a batch). A tool call gets an isError result with
 * the sign-in challenge; any other request gets the same text as an error. */
function appsLimitedResponse(body: unknown, text: string): unknown {
  const msgs = (Array.isArray(body) ? body : [body]).filter((m: any) => m && typeof m === 'object' && 'id' in m && typeof m.method === 'string')
  const replies = msgs.map((m: any) =>
    m.method === 'tools/call'
      ? {
          jsonrpc: '2.0',
          id: m.id,
          result: {
            content: [{ type: 'text', text }],
            isError: true,
            _meta: { 'mcp/www_authenticate': [appsChallenge('Sign in to WebAbility to keep scanning now')] },
          },
        }
      : { jsonrpc: '2.0', id: m.id, error: { code: -32001, message: text } },
  )
  return Array.isArray(body) ? replies : (replies[0] ?? { jsonrpc: '2.0', id: null, error: { code: -32001, message: text } })
}

// Sign-in flood limits (#201), per client IP. Each POST /authorize/start mints
// a device code on the platform API, and each unknown bearer token costs a
// platform whoami call; neither needs an account. Only FAILED token checks
// count, once per dead token per TOKEN_TTL_MS, so valid tokens never use this
// budget and a lockout cannot block a token the OAuth endpoints just issued.
const ANON_AUTH_START_PER_HOUR = Number(process.env.ANON_AUTH_START_PER_HOUR || 20)
const BAD_TOKEN_PER_HOUR = Number(process.env.BAD_TOKEN_PER_HOUR || 30)
// A valid consent link is single-use, but a leaked sid + cookie pair could be
// replayed until it expires, each replay costing a platform device-token call.
// Generous enough for a shared office NAT: one sign-in is a handful of hits.
const ANON_AUTH_COMPLETE_PER_HOUR = Number(process.env.ANON_AUTH_COMPLETE_PER_HOUR || 60)
const signInLimiter = createAnonLimiter()

// Operator calls run on the deploy's own WEBABILITY_API_KEY (no account
// behind them), so they are budgeted per IP per class. Separate counters from
// the anonymous ones: operator traffic must never consume a caller's budget,
// and a busy operator must not be capped by anonymous traffic (#227).
const OPERATOR_HEAVY_PER_HOUR = Number(process.env.OPERATOR_HEAVY_PER_HOUR || 600)
const OPERATOR_AI_PER_HOUR = Number(process.env.OPERATOR_AI_PER_HOUR || 150)
const OPERATOR_ACCOUNT_PER_HOUR = Number(process.env.OPERATOR_ACCOUNT_PER_HOUR || 300)
const operatorLimiter = createAnonLimiter()

function operatorLimit(cls: 'heavy' | 'ai' | 'account'): number {
  return cls === 'ai' ? OPERATOR_AI_PER_HOUR : cls === 'account' ? OPERATOR_ACCOUNT_PER_HOUR : OPERATOR_HEAVY_PER_HOUR
}

class JsonParseError extends Error {}

/** The JSON-RPC body, capped at MCP_MAX_BODY_BYTES (#199). */
async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const raw = (await readBodyCapped(req, MCP_MAX_BODY_BYTES)).toString('utf8')
  if (!raw) return undefined
  try {
    return JSON.parse(raw)
  } catch {
    throw new JsonParseError('request body is not valid JSON')
  }
}

/** 413, then close: the rest of the oversized body is never read. */
function sendTooLarge(res: ServerResponse, limit: number, jsonRpc: boolean) {
  res.setHeader('Connection', 'close')
  sendJson(
    res,
    413,
    jsonRpc
      ? { jsonrpc: '2.0', error: { code: -32600, message: `Request body is larger than ${limit} bytes.` }, id: null }
      : { error: 'invalid_request', error_description: `request body is larger than ${limit} bytes` },
  )
}

const httpServer = createHttpServer(async (req, res) => {
  // Every response from this origin gets them (#1457). Set before any branch
  // writes a status line, so a route added later cannot miss them; the OAuth
  // HTML pages override just the CSP (securityHeaders.ts).
  setSecurityHeaders(res)
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)
  // The caller's address for every rate budget below (OAuth sign-in and the
  // per-path gates); one read, so the proxies are only trusted once.
  const ip = clientIp(req.headers, req.socket.remoteAddress)

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

  if (req.method === 'POST' && url.pathname === '/authorize/start') {
    const gate = signInLimiter.allow(`${ip}:authstart`, ANON_AUTH_START_PER_HOUR)
    if (!gate.ok) {
      res.setHeader('Retry-After', String(gate.retryAfterS))
      // A client that treats 429 as a dead end has nowhere to go without a
      // sign-in signal; the metadata URL names the OAuth server. No
      // error="invalid_token": this caller never sent a token.
      res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${resourceMetadataUrl(MCP_PATH)}"`)
      sendJson(res, 429, { error: 'rate_limited', error_description: `Too many sign-in attempts from this network. Try again in ${Math.ceil(gate.retryAfterS / 60)} min.` })
      return
    }
  }

  // OAuth front door (metadata, DCR, authorize, token) — see oauth.ts.
  const oauthHooks: OAuthHooks = {
    onTokenIssued: rememberIssued,
    // oauth.ts charges this only after it has proven the session and the
    // binding cookie, so junk sids cannot spend a real user's budget.
    chargeComplete: () => signInLimiter.allow(`${ip}:authcomplete`, ANON_AUTH_COMPLETE_PER_HOUR),
  }
  try {
    if (await handleOAuth(req, res, url, oauthHooks)) return
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      sendTooLarge(res, err.limit, false)
      return
    }
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

  // Static server card (SEP-1649) for directories like Smithery.
  if (url.pathname === SERVER_CARD_PATH && req.method === 'GET') {
    try {
      const card = await getServerCard()
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
      })
      res.end(JSON.stringify(card))
    } catch (err) {
      console.error('[server-card] build error:', err)
      sendJson(res, 500, { error: 'server_error' })
    }
    return
  }

  // Humans who open the bare domain (e.g. from the dashboard card) get sent to
  // the setup docs — only /mcp (machines) and /health live here.
  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(302, { Location: 'https://www.webability.io/docs/mcp' })
    res.end()
    return
  }

  if (!MCP_PATHS.includes(url.pathname)) {
    sendJson(res, 404, { error: 'not_found' })
    return
  }
  const mcpPath = url.pathname

  // Refuse an oversized body before the token check and before reading it
  // (#199). A chunked body has no Content-Length: readJsonBody counts it.
  if (req.method === 'POST' && declaredTooLarge(req, MCP_MAX_BODY_BYTES)) {
    sendTooLarge(res, MCP_MAX_BODY_BYTES, true)
    return
  }

  // Auth is PARTIAL on /mcp. Anyone can initialize, list tools, and call the
  // free (DOM/scanner) tools anonymously — rate-limited per IP. A valid
  // per-user token lifts the limits and unlocks the account tools, which run
  // on that caller's account. /mcp/auth has no anonymous mode: a request
  // without a token gets 401 + WWW-Authenticate so the client signs in. A
  // GARBAGE token is a hard 401 on both paths (a caller who tried to
  // authenticate should learn their token is bad, not be silently downgraded
  // to anonymous; the MCP spec requires 401 for an invalid token). The shared
  // operator token is accepted too.
  const candidates = bearerCandidates(req)
  const badTokenKey = `${ip}:badtoken`
  // A rejected token is never selected. Otherwise the FIRST candidate wins:
  // Authorization is the caller's own token, and a stale x-webability-token
  // left in a client config must not run the call on another account just
  // because that account's token is still cached (#229).
  const usable = candidates.filter((t) => !isRejected(t))
  const first = usable[0]
  const cached = usable.find((t) => tokenCache.has(t))
  // One exception: under an active lockout an unknown first token would be
  // refused without a platform call, so a sibling the server already verified
  // wins. That is the Smithery case, where Authorization carries a gateway's
  // own hop and the user's token rides in x-webability-token.
  const locked = !first || tokenCache.has(first) ? false : !signInLimiter.full(badTokenKey, BAD_TOKEN_PER_HOUR).ok
  const token =
    candidates.find(matchesShared) ?? (locked && cached !== undefined ? cached : first) ?? candidates[0] ?? ''
  let authToken: string | undefined
  let anonymous = false
  let operator = false
  let tokenCheck: TokenCheck = { state: 'invalid' }
  const sendInvalidToken = () => {
    res.setHeader('WWW-Authenticate', wwwAuthenticate(mcpPath))
    sendJson(res, 401, {
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message:
          mcpPath === APPS_MCP_PATH
            ? 'Your WebAbility sign-in has expired. Reconnect WebAbility in ChatGPT to sign in again.'
            : 'Invalid or expired token. Reconnect (your client re-runs the sign-in), run `webability login` for a fresh token, ' +
              'or remove the Authorization and x-webability-token headers: the free scanning tools work without an account. ' +
              'Docs: https://www.webability.io/docs/mcp',
      },
      id: null,
    })
  }
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
    // Operator mode: no account, so account tools fall back to the deploy's own
    // WEBABILITY_API_KEY. That spend is ours, so the calls are budgeted per IP
    // and attributed to a constant operator distinct id (#227).
    authToken = undefined
    operator = true
  } else if (isRejected(token)) {
    // Known dead: a 401, not the 429 below, so the client re-runs sign-in.
    sendInvalidToken()
    return
  } else if (!tokenCache.has(token) && !signInLimiter.full(badTokenKey, BAD_TOKEN_PER_HOUR).ok) {
    // Too many failed token checks from this IP: refuse an unknown token
    // without asking the platform. A token already verified or just issued
    // by OAuth skips this.
    const gate = signInLimiter.full(badTokenKey, BAD_TOKEN_PER_HOUR)
    res.setHeader('Retry-After', String(gate.retryAfterS))
    sendJson(res, 429, {
      jsonrpc: '2.0',
      error: { code: -32001, message: `Too many invalid tokens from this network. Sign in again, or try this token in ${Math.ceil(gate.retryAfterS / 60)} min. The free scanning tools work now if you remove the Authorization and x-webability-token headers.` },
      id: null,
    })
    return
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
    // A concurrent request with this token may have recorded it during the
    // await above: spend the budget once per dead token, not once per request.
    if (!isRejected(token)) signInLimiter.allow(badTokenKey, BAD_TOKEN_PER_HOUR)
    rememberRejected(token)
    sendInvalidToken()
    return
  }

  // This server is stateless, so it never pushes on a standing GET stream. The
  // SDK would open one and send no bytes: no headers reach Cloudflare, it
  // answers 524 at 125s, and Cursor marks the server failed. 405 is the spec's
  // way to say there is no GET stream. Comes after auth so a client with no
  // token still gets the 401 that starts sign-in.
  if (req.method === 'GET') {
    res.setHeader('Allow', 'POST, DELETE, OPTIONS')
    sendJson(res, 405, { jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed: this server has no GET stream' }, id: null })
    return
  }

  try {
    const body = req.method === 'POST' ? await readJsonBody(req) : undefined


    if (anonymous) {
      // Every tool the body calls — a JSON-RPC batch must not slip past the
      // gate by hiding its calls in an array (see anonGate.ts).
      // Account tools are not refused here: their handlers return a sign-in
      // result before any browser or API work (server.ts).
      const tools = calledTools(body)
      for (const tool of tools) {
        const cls = anonLimitClass(tool)
        if (!cls) continue
        const limit = cls === 'ai' ? ANON_AI_PER_HOUR : ANON_HEAVY_PER_HOUR
        const gate = anonLimiter.allow(`${ip}:${cls}`, limit, anonCallCost(tool))
        if (!gate.ok) {
          res.setHeader('Retry-After', String(gate.retryAfterS))
          if (mcpPath === APPS_MCP_PATH) {
            // ChatGPT: a bare 429 is a dead end (no sign-in signal), and its
            // anonymous users share OpenAI's egress IPs, so they reach the cap
            // together. Answer each request with an isError tool result that
            // carries the sign-in challenge (a signed-in caller has no cap).
            sendJson(res, 200, appsLimitedResponse(body, appsAnonLimitMessage({ cls, limit, retryAfterS: gate.retryAfterS, resetAt: gate.resetAt })))
            return
          }
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

    if (operator) {
      // The operator token is one shared string, so a single leak or a runaway
      // script spends OUR account's API key with no account to bill. Budget it
      // per IP per class, per tool call in the body (a batch can hold many).
      for (const tool of calledTools(body)) {
        const cls = operatorLimitClass(tool)
        if (!cls) continue
        const limit = operatorLimit(cls)
        const gate = operatorLimiter.allow(`${ip}:operator:${cls}`, limit)
        if (!gate.ok) {
          res.setHeader('Retry-After', String(gate.retryAfterS))
          // Server-to-server callers read JSON, never a sign-in page: no
          // appsLimitedResponse here.
          sendJson(res, 429, {
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: operatorLimitMessage({ cls, limit, retryAfterS: gate.retryAfterS, resetAt: gate.resetAt }),
              data: { limit, perHours: 1, retryAfterSeconds: gate.retryAfterS, resetAt: new Date(gate.resetAt).toISOString() },
            },
            id: null,
          })
          return
        }
      }
    }

    // scan_html's in-process engine is ONE jsdom document per process. Past its
    // queue depth a call would wait behind an unknown number of multi-second
    // scans, so it is refused here, before the SDK sees the body — the caller
    // learns the wait from the protocol (503 + Retry-After), not only from
    // prose. The tool handler applies the same cap for stdio. See scanHtmlGate.
    const appsPath = mcpPath === APPS_MCP_PATH
    const refusal = scanHtmlBusyRefusal(body, appsPath)
    if (refusal) {
      res.setHeader('Retry-After', String(refusal.retryAfterSeconds))
      sendJson(res, refusal.status, refusal.body)
      return
    }

    // /mcp/apps (ChatGPT) declares per-tool securitySchemes and answers an
    // anonymous account-tool call with an isError + www_authenticate challenge.
    const server = createServer({
      remote: true,
      authToken,
      anonymous,
      operator,
      appsAuth: appsPath,
      // A scan_html cut at its deadline is a tool error in a 200 response — the
      // right status for a tool that failed, and no place for a header that
      // tells the caller when to come back. Set it here, while the response is
      // still ours: Node merges headers set this way into the writeHead() the
      // transport issues at flush time.
      onScanHtmlRetry: (seconds) => {
        if (!res.headersSent) res.setHeader('Retry-After', String(seconds))
      },
      ...(scanHtmlDeadlineOverrideMs > 0 ? { scanHtmlDeadlineMs: scanHtmlDeadlineOverrideMs } : {}),
    })
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
    res.on('close', () => {
      transport.close().catch(() => {})
      server.close().catch(() => {})
    })
    await server.connect(transport)
    await transport.handleRequest(req, res, body)
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      if (!res.headersSent) sendTooLarge(res, err.limit, true)
      return
    }
    if (err instanceof JsonParseError) {
      if (!res.headersSent) sendJson(res, 400, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error: request body is not valid JSON' }, id: null })
      return
    }
    console.error('[mcp-http] request error:', err)
    if (!res.headersSent) {
      sendJson(res, 500, { jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null })
    }
  }
})

// The OAuth server cannot issue a client_id or a bound refresh token without
// a signing key, and the old fallbacks (MCP_AUTH_TOKEN, then a random key per
// boot) either handed the shared operator secret a signing role or silently
// invalidated every client on restart. Refuse to start instead (#227).
try {
  assertSigningSecret()
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
}

httpServer.listen(PORT, () => {
  console.error(`WebAbility MCP (Streamable HTTP) listening on :${PORT}${MCP_PATH}`)
  // Stated once, because a wrong TRUSTED_PROXY_HOPS / TRUST_CF_CONNECTING_IP
  // silently merges every caller into one bucket or lets one caller mint many.
  console.error(`[mcp-http] client ip: ${describeClientIpPolicy()}`)
})
