/**
 * OAuth 2.1 authorization layer for the hosted MCP endpoint.
 *
 * Directory clients (Claude's connector directory, and any MCP client that
 * follows the spec's auth flow) discover auth via RFC 9728 protected-resource
 * metadata, register with RFC 7591 dynamic client registration, and run an
 * authorization-code + PKCE flow. We have no first-party OAuth provider, so
 * /authorize bridges to the platform's existing device-code login: the page
 * starts a device session against the API and sends the user, in the same
 * window, to the verification page `webability login` uses. That page shows a
 * consent screen for the named client and returns to /authorize/complete, which
 * turns the resulting WebAbility token into the OAuth access token. Everything
 * happens in one window: app reviewers (OpenAI rejected a two-tab flow) and
 * popup-based clients never have to find their way back to another tab. /mcp then validates it exactly as before
 * (per-user token, so account tools run as that caller), so nothing about the
 * transport or account model changes — this is purely a front door.
 *
 * State model, sized for a single container:
 * - client_id is a self-contained HMAC-signed blob (no client store, so
 *   registrations survive restarts — clients hold client_id for months).
 * - authorize sessions and auth codes are in-memory with short TTLs; a
 *   restart mid-login just means the user clicks "connect" again.
 */
import type { IncomingMessage, ServerResponse } from 'http'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto'
import { APPS_MCP_PATH, MCP_PATH, PUBLIC_URL, SIGN_IN_MCP_PATH, resourceMetadataUrl } from './signIn.js'
import type { AnonGateResult } from './anonGate.js'
import { OAUTH_MAX_BODY_BYTES, readBodyCapped } from './bodyLimit.js'
import { setSecurityHeaders } from './securityHeaders.js'

const ISSUER = PUBLIC_URL
const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

// HMAC key for client_id and refresh-token-binding blobs. It is REQUIRED: a
// per-boot random silently invalidates every issued client_id and bound
// refresh token on restart, and falling back to MCP_AUTH_TOKEN made the shared
// operator secret a signing key — whoever held it could mint a client_id
// naming any redirect_uri (#227, #229-3).
export const SIGNING_SECRET_ENV = 'OAUTH_SIGNING_SECRET'
const SIGNING_SECRET = (process.env[SIGNING_SECRET_ENV] || '').trim()

/** Fatal at boot (http.ts). A function, not a module-load throw, so
 * authorizePage() stays importable (and testable) without any env. */
export function assertSigningSecret(): void {
  if (SIGNING_SECRET) return
  throw new Error(
    `[oauth] ${SIGNING_SECRET_ENV} is required: it signs OAuth client_ids and refresh-token bindings. ` +
      'Set it to a long random value (openssl rand -hex 32) in the deploy environment; ' +
      'rotating it forces every connected client to register and sign in again.',
  )
}

const SESSION_TTL_MS = 10 * 60 * 1000
const CODE_TTL_MS = 5 * 60 * 1000

interface AuthParams {
  client_id: string
  redirect_uri: string
  state: string
  code_challenge: string
  /** display-only, derived server-side from the signed client_id — not client input */
  client_label: string
}
interface Session extends AuthParams {
  deviceCode: string
  /** platform consent page, with the return_to that brings the user back */
  continueUrl: string
  /** random browser binding, stored only in this session and in the caller's
   * HttpOnly cookie — it never appears in a URL (#228) */
  binding: string
  exp: number
}
interface IssuedCode {
  token: string
  /** Platform refresh token (absent if the platform did not send one) */
  refresh_token?: string
  code_challenge: string
  redirect_uri: string
  client_id: string
  exp: number
}

const sessions = new Map<string, Session>()
const codes = new Map<string, IssuedCode>()

function sweep() {
  const now = Date.now()
  for (const [k, v] of sessions) if (v.exp < now) sessions.delete(k)
  for (const [k, v] of codes) if (v.exp < now) codes.delete(k)
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function sign(payload: string): string {
  // Never HMAC with an empty key: that is a public constant, so anyone could
  // forge a client_id. http.ts refuses to boot without the env; this guards
  // every other entry point (tests, a future embedder).
  assertSigningSecret()
  return b64url(createHmac('sha256', SIGNING_SECRET).update(payload).digest())
}

/** Self-contained client_id: base64url(JSON{r: redirect_uris, n: name, iat}) + "." + HMAC.
 * The name is signed in so the consent page can say WHO is asking — an
 * attacker who registers their own client gets their own name shown, not a
 * generic "this app" they can hide behind. */
function mintClientId(redirectUris: string[], name: string): string {
  const payload = b64url(Buffer.from(JSON.stringify({ r: redirectUris, n: name.slice(0, 64), iat: Math.floor(Date.now() / 1000) })))
  return `${payload}.${sign(payload)}`
}
function parseClientId(clientId: string): { redirectUris: string[]; name: string } | null {
  const dot = clientId.lastIndexOf('.')
  if (dot < 1) return null
  const payload = clientId.slice(0, dot)
  const mac = Buffer.from(clientId.slice(dot + 1))
  const expected = Buffer.from(sign(payload))
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return null
  try {
    const parsed = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'))
    if (!Array.isArray(parsed.r) || !parsed.r.every((u: unknown) => typeof u === 'string')) return null
    return { redirectUris: parsed.r, name: typeof parsed.n === 'string' ? parsed.n : '' }
  } catch {
    return null
  }
}

/** Refresh tokens handed to clients are bound to the client that signed in:
 * base64url(JSON{c: sha256(client_id), t: platform refresh token}) + "." + HMAC.
 * A token issued to one client cannot be redeemed or rotated through another. */
function clientHash(clientId: string): string {
  return b64url(createHash('sha256').update(clientId).digest())
}
function bindRefreshToken(platformToken: string, clientId: string): string {
  const payload = b64url(Buffer.from(JSON.stringify({ c: clientHash(clientId), t: platformToken })))
  return `${payload}.${sign(payload)}`
}
/** The platform refresh token inside a bound token, or null unless it was issued to this client_id. */
function unbindRefreshToken(token: string, clientId: string): string | null {
  if (!parseClientId(clientId)) return null
  const dot = token.lastIndexOf('.')
  if (dot < 1) return null
  const payload = token.slice(0, dot)
  const mac = Buffer.from(token.slice(dot + 1))
  const expected = Buffer.from(sign(payload))
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return null
  try {
    const parsed = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'))
    if (parsed.c !== clientHash(clientId) || typeof parsed.t !== 'string' || !parsed.t) return null
    return parsed.t
  } catch {
    return null
  }
}

/** https anywhere; plain http only for loopback development clients. */
function validRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri)
    if (u.protocol === 'https:') return true
    if (u.protocol === 'http:') return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]'
    return false
  } catch {
    return false
  }
}

// --- browser binding (#228) -------------------------------------------------
// /authorize/complete used to be the only thing tying an approval to a
// browser, and the sid in return_to was the whole of it — so whoever minted
// the sid could collect the code for a client of their choosing (the consent
// screen names the client, but the victim is already clicking "allow"). The
// session now also gets a random binding that travels ONLY in an HttpOnly
// cookie set by this origin: the platform page and the browser history never
// see it, and a complete without the matching cookie cannot hand out a code.
const BINDING_COOKIE = 'wa_oauth'
const BINDING_PATH = '/authorize'
// Tabs: one cookie per origin, so concurrent sign-ins on this origin each
// append an entry and the newest few are kept. Older ones fall off.
const BINDING_MAX_ENTRIES = 4
const BINDING_ENTRY_RE = /^([0-9a-f]{32})\.([0-9a-f]{32})$/
const COOKIE_SECURE = ISSUER.startsWith('https://') ? '; Secure' : ''

/** One cookie by name, first match. Manual split: `req.cookies` needs a dep. */
function readCookie(req: IncomingMessage, name: string): string {
  const header = req.headers.cookie
  if (!header) return ''
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return ''
}

/** {{sid, binding}} pairs from the cookie, malformed entries dropped. */
function bindingEntries(req: IncomingMessage): Array<{ sid: string; binding: string }> {
  const raw = readCookie(req, BINDING_COOKIE)
  if (!raw) return []
  const entries: Array<{ sid: string; binding: string }> = []
  for (const part of raw.split('~')) {
    const m = BINDING_ENTRY_RE.exec(part)
    if (m) entries.push({ sid: m[1], binding: m[2] })
  }
  return entries
}

/** Set-Cookie value for this list; an empty list clears the cookie. */
function bindingCookieHeader(entries: Array<{ sid: string; binding: string }>): string {
  const kept = entries.slice(-BINDING_MAX_ENTRIES)
  const value = kept.map((e) => `${e.sid}.${e.binding}`).join('~')
  const maxAge = kept.length ? SESSION_TTL_MS / 1000 : 0
  return `${BINDING_COOKIE}=${value}; Path=${BINDING_PATH}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${COOKIE_SECURE}`
}

/** Constant-time compare of two hex bindings (length-checked: timingSafeEqual throws on a mismatch). */
function sameBinding(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

/** Drop one session's cookie entry; other tabs' entries survive. */
function forgetBinding(req: IncomingMessage, res: ServerResponse, sid: string): void {
  res.setHeader('Set-Cookie', bindingCookieHeader(bindingEntries(req).filter((e) => e.sid !== sid)))
}

interface TokenPayload {
  token?: string
  refreshToken?: string
  error?: string
}

// Platform output is unvalidated: keep only the fields we use, as strings.
// `in` narrows to `unknown` without a cast, so a non-string stays rejected.

interface DeviceCode {
  deviceCode?: string
  userCode?: string
  verificationUrl?: string
}

async function readDeviceCode(res: Response): Promise<DeviceCode> {
  const body: unknown = await res.json().catch(() => null)
  if (!body || typeof body !== 'object') return {}
  return {
    deviceCode: stringOrUndefined('deviceCode' in body ? body.deviceCode : undefined),
    userCode: stringOrUndefined('userCode' in body ? body.userCode : undefined),
    verificationUrl: stringOrUndefined('verificationUrl' in body ? body.verificationUrl : undefined),
  }
}

async function readTokenPayload(res: Response): Promise<TokenPayload> {
  const body: unknown = await res.json().catch(() => null)
  if (!body || typeof body !== 'object') return {}
  return {
    token: stringOrUndefined('token' in body ? body.token : undefined),
    refreshToken: stringOrUndefined('refreshToken' in body ? body.refreshToken : undefined),
    error: stringOrUndefined('error' in body ? body.error : undefined),
  }
}

/** A non-empty string, or undefined. Empty is absence for every field here. */
function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined
}

function json(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(body))
}

/** Throws BodyTooLargeError past OAUTH_MAX_BODY_BYTES; http.ts answers 413 (#199). */
async function readBody(req: IncomingMessage): Promise<string> {
  return (await readBodyCapped(req, OAUTH_MAX_BODY_BYTES)).toString('utf8')
}

/** /token accepts application/x-www-form-urlencoded (the OAuth default) or JSON. */
async function readParams(req: IncomingMessage): Promise<Record<string, string>> {
  const raw = await readBody(req)
  if (!raw) return {}
  if ((req.headers['content-type'] || '').includes('application/json')) {
    try {
      const parsed = JSON.parse(raw)
      if (typeof parsed !== 'object' || !parsed) return {}
      // JSON lets a caller send objects/arrays where strings are declared —
      // drop anything non-string so the validators can trust their inputs.
      return Object.fromEntries(Object.entries(parsed).filter(([, v]) => typeof v === 'string')) as Record<string, string>
    } catch {
      return {}
    }
  }
  return Object.fromEntries(new URLSearchParams(raw))
}
/** RFC 6749 §2.3.1: a confidential client sends its credentials as
 * `Authorization: Basic base64(urlencode(id):urlencode(secret))`. We only need
 * the id — clients here are public and PKCE is the proof, so a secret is never
 * verified, only tolerated. */
function basicClientId(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization
  if (!header) return undefined
  const [scheme, encoded] = header.split(' ')
  if (!scheme || scheme.toLowerCase() !== 'basic' || !encoded) return undefined
  const decoded = Buffer.from(encoded, 'base64').toString('utf8')
  const separator = decoded.indexOf(':')
  if (separator < 0) return undefined
  const id = decoded.slice(0, separator)
  // The spec form-encodes each part; some clients send the raw id. Decode when
  // it parses, keep the raw text when it does not, so a stray `%` never turns
  // into a thrown error on the token path.
  try {
    return decodeURIComponent(id)
  } catch {
    return id
  }
}

/** RFC 6749 §2.3.1 lets a client put client_id in the body OR in the Basic
 * header. Accept either; when both appear they must agree, or a client could
 * redeem its own code while naming someone else's client.
 * Returns null for a conflict, so the caller can answer invalid_grant. */
function resolveClientId(req: IncomingMessage, body: Record<string, string>): string | undefined | null {
  const header = basicClientId(req)
  const fromBody = body.client_id
  if (header && fromBody && header !== fromBody) return null
  return header || fromBody
}

/** Exact match, except loopback redirects may vary the port (RFC 8252 §7.3 —
 * native clients bind an ephemeral localhost port per run). */
function redirectUriMatches(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true
  let candidate: URL
  try {
    candidate = new URL(uri)
  } catch {
    return false
  }
  const loopback = candidate.protocol === 'http:' && (candidate.hostname === 'localhost' || candidate.hostname === '127.0.0.1' || candidate.hostname === '[::1]')
  if (!loopback) return false
  return registered.some((r) => {
    try {
      const reg = new URL(r)
      return reg.protocol === candidate.protocol && reg.hostname === candidate.hostname && reg.pathname === candidate.pathname && reg.search === candidate.search
    } catch {
      return false
    }
  })
}

/** The only scope this server issues. The access token is the caller's own
 * WebAbility token, so `mcp` names the grant rather than a narrower privilege
 * set, and it is advertised in metadata only: RFC 6749 §3.3 lets a server
 * ignore scopes it does not issue, so a requested `openid offline_access`,
 * `profile`, `mcp` or anything else is ignored and the default grant is
 * issued. Refusing would lock out real clients (ChatGPT, Claude, Cursor) that
 * send those scopes unconditionally. */
const SUPPORTED_SCOPE = 'mcp'

/** A validation failure in OAuth wire terms: `code` is the RFC 6749 §4.1.2.1
 * error, `error` the human-readable description of the same. */
type AuthError = { ok: false; code: string; error: string }

function validateAuthRequest(q: Record<string, unknown>): { ok: true; params: AuthParams } | AuthError {
  const clientId = typeof q.client_id === 'string' ? q.client_id : ''
  const client = parseClientId(clientId)
  if (!client) return { ok: false, code: 'invalid_request', error: 'unknown client_id — register at /register first' }
  const redirectUri = typeof q.redirect_uri === 'string' ? q.redirect_uri : ''
  if (!redirectUriMatches(client.redirectUris, redirectUri)) return { ok: false, code: 'invalid_request', error: 'redirect_uri is not registered for this client' }
  if (q.response_type !== 'code') return { ok: false, code: 'unsupported_response_type', error: 'response_type must be "code"' }
  const codeChallenge = typeof q.code_challenge === 'string' ? q.code_challenge : ''
  if (!codeChallenge || q.code_challenge_method !== 'S256') return { ok: false, code: 'invalid_request', error: 'PKCE with S256 is required' }
  const host = (() => {
    try {
      return new URL(redirectUri).host
    } catch {
      return ''
    }
  })()
  return {
    ok: true,
    params: {
      client_id: clientId,
      redirect_uri: redirectUri,
      state: typeof q.state === 'string' ? q.state : '',
      code_challenge: codeChallenge,
      client_label: client.name ? `${client.name} (${host})` : host,
    },
  }
}

const AS_METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  registration_endpoint: `${ISSUER}/register`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
  scopes_supported: [SUPPORTED_SCOPE],
  service_documentation: 'https://www.webability.io/docs/mcp',
}

/** RFC 9728 metadata for one MCP path: /mcp (anonymous allowed), /mcp/auth
 * (sign-in path) or /mcp/apps (ChatGPT, anonymous allowed).
 * The issued access token is the caller's WebAbility token, valid on every
 * path: the `resource` value tells the client which URL it is signing in
 * for; it is not an audience binding. The bare /.well-known path serves the
 * /mcp document. */
const resourceMetadata = (mcpPath: string) => ({
  resource: `${ISSUER}${mcpPath}`,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ['header'],
  scopes_supported: [SUPPORTED_SCOPE],
  resource_documentation: 'https://www.webability.io/docs/mcp',
})

function escapeJsonForHtml(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c')
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** A plain status page for /authorize/complete outcomes that do not redirect. */
function messagePage(res: ServerResponse, status: number, title: string, message: string, link?: { href: string; label: string }) {
  setSecurityHeaders(res, { html: true })
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f1115;color:#e8eaed;display:grid;place-items:center;min-height:100vh}main{max-width:26rem;padding:2rem;text-align:center}p{color:#9aa0a6;line-height:1.5}a{display:inline-block;margin-top:1rem;padding:.6rem 1.4rem;border-radius:.5rem;background:#2563eb;color:#fff;text-decoration:none;font-weight:600}</style></head>
<body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${link ? `<a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>` : ''}</main></body></html>`)
}

/** The /authorize page: starts the device-code session, then sends this same
 * window to the platform sign-in and consent page. */
export function authorizePage(params: AuthParams): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to WebAbility</title>
<style>
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f1115; color: #e8eaed; display: grid; place-items: center; min-height: 100vh; }
  main { max-width: 26rem; padding: 2rem; text-align: center; }
  h1 { font-size: 1.25rem; font-weight: 600; }
  p { color: #9aa0a6; line-height: 1.5; }
  #status { margin-top: 1.5rem; font-size: 0.9rem; color: #9aa0a6; }
  .err { color: #f28b82; }
  .agent { margin-top: 2rem; font-size: 0.85rem; }
</style>
</head>
<body>
<main>
  <h1>Connect to WebAbility</h1>
  <p id="intro">Sign in with your WebAbility account.</p>
  <p id="status" role="status">Starting sign-in…</p>
  <p class="agent">AI agent with its own AgentMail inbox? Choose <strong>Sign in with AgentID</strong> on the sign-in page. A new agent gets its own WebAbility account.</p>
</main>
<script>
const AUTH = ${escapeJsonForHtml(params)};
document.getElementById('intro').textContent =
  'Sign in with your WebAbility account to let ' + (AUTH.client_label || 'this app') +
  ' scan and audit for accessibility on your behalf.';
const statusEl = () => document.getElementById('status');
async function post(path, body) {
  // same-origin is the default; stated because the response's Set-Cookie IS the
  // browser binding that /authorize/complete later demands back.
  const res = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return res.json();
}
(async () => {
  try {
    const start = await post('/authorize/start', AUTH);
    if (!start.sid) throw new Error(start.error || 'could not start sign-in');
    if (!/^https:\\/\\//.test(start.continueUrl)) throw new Error('bad sign-in URL');
    statusEl().textContent = 'Opening WebAbility sign-in…';
    // replace(): Back from the platform page must not re-run this script
    // and mint another device code.
    location.replace(start.continueUrl);
  } catch (err) {
    statusEl().className = 'err';
    statusEl().textContent = String(err && err.message || err);
  }
})();
</script>
</body>
</html>`
}

/** RFC 9728 §5.1 challenge — tells spec-following clients where auth lives. */
export function wwwAuthenticate(mcpPath: string = MCP_PATH): string {
  return `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrl(mcpPath)}"`
}

/** refresh_token grant: the platform verifies the refresh token and rotates both tokens. */
async function refreshGrant(boundToken: string | undefined, clientId: string | undefined, res: ServerResponse, onTokenIssued?: (token: string) => void): Promise<void> {
  if (!boundToken) {
    json(res, 400, { error: 'invalid_request', error_description: 'refresh_token is required' })
    return
  }
  const refreshToken = clientId ? unbindRefreshToken(boundToken, clientId) : null
  if (!refreshToken) {
    json(res, 400, { error: 'invalid_grant', error_description: 'refresh_token is invalid or was not issued to this client' })
    return
  }
  let apiRes: Response
  try {
    apiRes = await fetch(`${API_URL}/cli/refresh-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    })
  } catch (err) {
    console.error('[oauth] refresh-token request failed:', err)
    json(res, 503, { error: 'temporarily_unavailable', error_description: 'Could not reach the WebAbility sign-in service.' })
    return
  }
  const payload = await readTokenPayload(apiRes)
  if (apiRes.status === 400 || apiRes.status === 401) {
    json(res, 400, { error: 'invalid_grant', error_description: 'refresh_token is invalid, expired or revoked' })
    return
  }
  if (!apiRes.ok || !payload.token) {
    console.error(`[oauth] refresh-token returned ${apiRes.status}`)
    json(res, 503, { error: 'temporarily_unavailable', error_description: 'The WebAbility sign-in service returned an error.' })
    return
  }
  onTokenIssued?.(payload.token)
  // No `scope` (RFC 6749 §5.1 makes it optional when it is the requested one):
  // the access token is the caller's WebAbility account token, so naming a
  // scope here would promise a narrower grant than the token actually is.
  json(res, 200, {
    access_token: payload.token,
    token_type: 'Bearer',
    ...(payload.refreshToken ? { refresh_token: bindRefreshToken(payload.refreshToken, clientId!) } : {}),
  })
}

/** Callbacks the HTTP layer owns: token bookkeeping and the sign-in rate budget. */
export interface OAuthHooks {
  onTokenIssued?: (token: string) => void
  /** Charged only after a valid session AND cookie match, so junk probes against
   * /authorize/complete cannot burn a shared egress IP's budget (#228). */
  chargeComplete?: () => AnonGateResult
}

/** Route OAuth endpoints. Returns true when the request was handled here. */
export async function handleOAuth(req: IncomingMessage, res: ServerResponse, url: URL, hooks: OAuthHooks = {}): Promise<boolean> {
  sweep()
  const path = url.pathname

  if (
    req.method === 'GET' &&
    (path === '/.well-known/oauth-authorization-server' ||
      path === `/.well-known/oauth-authorization-server${MCP_PATH}` ||
      path === `/.well-known/oauth-authorization-server${SIGN_IN_MCP_PATH}` ||
      path === `/.well-known/oauth-authorization-server${APPS_MCP_PATH}`)
  ) {
    json(res, 200, AS_METADATA)
    return true
  }
  if (req.method === 'GET' && (path === '/.well-known/oauth-protected-resource' || path === `/.well-known/oauth-protected-resource${MCP_PATH}`)) {
    json(res, 200, resourceMetadata(MCP_PATH))
    return true
  }
  if (req.method === 'GET' && path === `/.well-known/oauth-protected-resource${SIGN_IN_MCP_PATH}`) {
    json(res, 200, resourceMetadata(SIGN_IN_MCP_PATH))
    return true
  }
  if (req.method === 'GET' && path === `/.well-known/oauth-protected-resource${APPS_MCP_PATH}`) {
    json(res, 200, resourceMetadata(APPS_MCP_PATH))
    return true
  }

  if (path === '/register' && req.method === 'POST') {
    let body: any
    const raw = await readBody(req)
    try {
      body = JSON.parse(raw || '{}')
    } catch {
      json(res, 400, { error: 'invalid_client_metadata', error_description: 'body must be JSON' })
      return true
    }
    const uris = body?.redirect_uris
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u: unknown) => typeof u === 'string' && validRedirectUri(u))) {
      json(res, 400, { error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https URLs (or http on localhost)' })
      return true
    }
    // Clients are public: PKCE is the proof, so a secret is never checked. But
    // strict clients (GoHighLevel Agent Studio) abort unless registration echoes
    // the method they asked for and hands back a secret, so echo and mint one.
    const requested = body?.token_endpoint_auth_method
    const confidential = requested === 'client_secret_basic' || requested === 'client_secret_post'
    json(res, 201, {
      client_id: mintClientId(uris, typeof body?.client_name === 'string' ? body.client_name : ''),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: uris,
      token_endpoint_auth_method: confidential ? requested : 'none',
      ...(confidential ? { client_secret: b64url(randomBytes(32)), client_secret_expires_at: 0 } : {}),
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: typeof body?.client_name === 'string' ? body.client_name : undefined,
    })
    return true
  }

  if (path === '/authorize' && req.method === 'GET') {
    const q = Object.fromEntries(url.searchParams)
    const checked = validateAuthRequest(q)
    // Invalid client or redirect_uri must never redirect (open-redirect risk) —
    // show the error on our own page instead.
    if (!checked.ok) {
      setSecurityHeaders(res, { html: true })
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' })
      const detail = `${checked.code}: ${checked.error}`.replace(/</g, '&lt;')
      res.end(`<!doctype html><meta charset="utf-8"><title>Invalid request</title><p style="font-family:sans-serif">Invalid authorization request: ${detail}</p>`)
      return true
    }
    setSecurityHeaders(res, { html: true })
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(authorizePage(checked.params))
    return true
  }

  if (path === '/authorize/start' && req.method === 'POST') {
    // The page echoes back the params the GET /authorize handler already
    // validated (minus response_type/method, which are fixed) — re-check the
    // security-relevant ones so a hand-crafted POST can't skip them.
    const body = await readParams(req)
    const checked = validateAuthRequest({ ...body, response_type: 'code', code_challenge_method: 'S256' })
    if (!checked.ok) {
      json(res, 400, { error: checked.code, error_description: checked.error })
      return true
    }
    try {
      const apiRes = await fetch(`${API_URL}/cli/device-code`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      if (!apiRes.ok) throw new Error(`device-code returned ${apiRes.status}`)
      const { deviceCode, userCode, verificationUrl } = await readDeviceCode(apiRes)
      if (!deviceCode || !verificationUrl) throw new Error('device-code response incomplete')
      const sid = randomBytes(16).toString('hex')
      const binding = randomBytes(16).toString('hex')
      const continueUrl = new URL(verificationUrl)
      // The sid is a handle, not a capability: /authorize/complete also demands
      // the HttpOnly cookie below, so this link is useless in another browser.
      continueUrl.searchParams.set('return_to', `${ISSUER}/authorize/complete?sid=${sid}`)
      continueUrl.searchParams.set('client', checked.params.client_label)
      sessions.set(sid, { ...checked.params, deviceCode, continueUrl: continueUrl.toString(), binding, exp: Date.now() + SESSION_TTL_MS })
      res.setHeader('Set-Cookie', bindingCookieHeader([...bindingEntries(req), { sid, binding }]))
      json(res, 200, { sid, continueUrl: continueUrl.toString(), userCode })
    } catch (err) {
      console.error('[oauth] device-code start failed:', err)
      json(res, 502, { error: 'Could not reach the WebAbility sign-in service. Try again in a moment.' })
    }
    return true
  }

  if (path === '/authorize/complete' && req.method === 'GET') {
    const sid = url.searchParams.get('sid') || ''
    const session = sessions.get(sid)
    if (!session || session.exp < Date.now()) {
      if (session) sessions.delete(sid)
      forgetBinding(req, res, sid)
      messagePage(res, 400, 'Sign-in expired', 'This sign-in link has expired. Go back to the app and connect WebAbility again.')
      return true
    }
    // The cookie is the browser check: without a matching entry this request
    // did not start the sign-in, so it must not collect the code (#228). The
    // session survives — the real browser can still finish, and a wrong guess
    // neither reveals nor destroys it.
    const bound = bindingEntries(req).find((e) => e.sid === sid)
    if (!bound || !sameBinding(bound.binding, session.binding)) {
      messagePage(
        res,
        400,
        'Finish signing in from the same browser',
        'This sign-in was started in another browser or tab. Go back to the app that opened it and connect WebAbility there.',
      )
      return true
    }
    // Charged after the session and cookie are proven, so random sids from a
    // shared IP cannot lock a real user out of finishing.
    const budget = hooks.chargeComplete?.()
    if (budget && !budget.ok) {
      res.setHeader('Retry-After', String(budget.retryAfterS))
      messagePage(res, 429, 'Too many sign-in attempts', `Too many sign-in attempts from this network. Try again in ${Math.ceil(budget.retryAfterS / 60)} min.`)
      return true
    }
    let deviceToken: TokenPayload = {}
    let deviceTokenOk = false
    try {
      const apiRes = await fetch(`${API_URL}/cli/device-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceCode: session.deviceCode }),
      })
      // A rate limit or outage says nothing about approval: keep the session
      // so a reload of the 503 page below completes it.
      if (apiRes.status === 429 || apiRes.status >= 500) throw new Error(`device-token returned ${apiRes.status}`)
      // Approval is "2xx AND a token in the body": the platform answers
      // pending with HTTP 202 + {error: "authorization_pending"}, and 202 is
      // ok:true to fetch — status alone says nothing.
      deviceTokenOk = apiRes.ok
      deviceToken = await readTokenPayload(apiRes)
    } catch (err) {
      console.error('[oauth] device-token request failed:', err)
      messagePage(res, 503, 'Sign-in service unavailable', 'Could not reach the WebAbility sign-in service. Reload this page in a moment.')
      return true
    }
    if (deviceTokenOk && deviceToken.token) {
      sessions.delete(sid)
      forgetBinding(req, res, sid)
      const code = b64url(randomBytes(32))
      codes.set(code, {
        token: deviceToken.token,
        refresh_token: deviceToken.refreshToken,
        code_challenge: session.code_challenge,
        redirect_uri: session.redirect_uri,
        client_id: session.client_id,
        exp: Date.now() + CODE_TTL_MS,
      })
      const redirect = new URL(session.redirect_uri)
      redirect.searchParams.set('code', code)
      if (session.state) redirect.searchParams.set('state', session.state)
      res.writeHead(302, { Location: redirect.toString(), 'Cache-Control': 'no-store' })
      res.end()
      return true
    }
    if (deviceToken.error === 'expired') {
      sessions.delete(sid)
      forgetBinding(req, res, sid)
      messagePage(res, 400, 'Sign-in expired', 'This sign-in link has expired. Go back to the app and connect WebAbility again.')
      return true
    }
    // Back button or a skipped consent click: send them to approve again.
    messagePage(res, 200, 'Not connected yet', 'You have not allowed access yet.', { href: session.continueUrl, label: 'Continue to WebAbility' })
    return true
  }

  if (path === '/token' && req.method === 'POST') {
    const p = await readParams(req)
    const clientId = resolveClientId(req, p)
    if (clientId === null) {
      json(res, 400, { error: 'invalid_grant', error_description: 'client_id in the body does not match the Authorization header' })
      return true
    }
    if (p.grant_type === 'refresh_token') {
      await refreshGrant(p.refresh_token, clientId, res, hooks.onTokenIssued)
      return true
    }
    if (p.grant_type !== 'authorization_code') {
      json(res, 400, { error: 'unsupported_grant_type' })
      return true
    }
    // A requested `scope` is ignored (RFC 6749 §3.3): absent, `mcp`,
    // `openid offline_access` and anything else all redeem the code and get the
    // default grant.
    const issued = p.code ? codes.get(p.code) : undefined
    if (!issued || issued.exp < Date.now()) {
      if (p.code) codes.delete(p.code)
      json(res, 400, { error: 'invalid_grant', error_description: 'code is invalid or expired' })
      return true
    }
    // Authorization codes are single-use (RFC 6749 §4.1.2): burn the code on the
    // first redemption attempt, before validating redirect_uri/client_id/PKCE, so
    // a failed check cannot be retried against the same code within its TTL.
    codes.delete(p.code)
    if (issued.redirect_uri !== p.redirect_uri || issued.client_id !== clientId) {
      json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri or client_id mismatch' })
      return true
    }
    const challenge = b64url(createHash('sha256').update(p.code_verifier || '').digest())
    if (challenge !== issued.code_challenge) {
      json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' })
      return true
    }
    // The access token is a 30-day WebAbility JWT. No expires_in: the client
    // learns it expired from a 401 on /mcp/auth, then uses refresh_token.
    // No `scope` either: RFC 6749 §5.1 makes it optional when it is the
    // requested one, and this token carries the caller's whole account — a
    // `scope: "mcp"` here would read as a narrower grant than it is (C2).
    hooks.onTokenIssued?.(issued.token)
    json(res, 200, { access_token: issued.token, token_type: 'Bearer', ...(issued.refresh_token ? { refresh_token: bindRefreshToken(issued.refresh_token, issued.client_id) } : {}) })
    return true
  }

  return false
}
