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
import { MCP_PATH, PUBLIC_URL, SIGN_IN_MCP_PATH, resourceMetadataUrl } from './signIn.js'
import { OAUTH_MAX_BODY_BYTES, readBodyCapped } from './bodyLimit.js'

const ISSUER = PUBLIC_URL
const API_URL = process.env.WEBABILITY_API_URL || process.env.ABILYO_API_URL || 'https://api.webability.io'

// HMAC key for client_id blobs. Losing it only forces clients through one
// re-registration (DCR is automatic), so a per-boot fallback is acceptable —
// but set OAUTH_SIGNING_SECRET in the deploy so restarts are seamless.
const SIGNING_SECRET = process.env.OAUTH_SIGNING_SECRET || process.env.MCP_AUTH_TOKEN || randomBytes(32).toString('hex')

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

function validateAuthRequest(q: Record<string, unknown>): { ok: true; params: AuthParams } | { ok: false; error: string } {
  const clientId = typeof q.client_id === 'string' ? q.client_id : ''
  const client = parseClientId(clientId)
  if (!client) return { ok: false, error: 'unknown client_id — register at /register first' }
  const redirectUri = typeof q.redirect_uri === 'string' ? q.redirect_uri : ''
  if (!redirectUriMatches(client.redirectUris, redirectUri)) return { ok: false, error: 'redirect_uri is not registered for this client' }
  if (q.response_type !== 'code') return { ok: false, error: 'response_type must be "code"' }
  const codeChallenge = typeof q.code_challenge === 'string' ? q.code_challenge : ''
  if (!codeChallenge || q.code_challenge_method !== 'S256') return { ok: false, error: 'PKCE with S256 is required' }
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
  token_endpoint_auth_methods_supported: ['none'],
  scopes_supported: ['mcp'],
  service_documentation: 'https://www.webability.io/docs/mcp',
}

/** RFC 9728 metadata for one MCP path: /mcp (anonymous allowed) or /mcp/auth (sign-in path).
 * The issued access token is the caller's WebAbility token, valid on both
 * paths: the `resource` value tells the client which URL it is signing in
 * for; it is not an audience binding. The bare /.well-known path serves the
 * /mcp document. */
const resourceMetadata = (mcpPath: string) => ({
  resource: `${ISSUER}${mcpPath}`,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ['header'],
  scopes_supported: ['mcp'],
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
  const res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
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
async function refreshGrant(boundToken: string | undefined, clientId: string | undefined, res: ServerResponse): Promise<void> {
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
  const payload = (await apiRes.json().catch(() => ({}))) as any
  if (apiRes.status === 400 || apiRes.status === 401) {
    json(res, 400, { error: 'invalid_grant', error_description: 'refresh_token is invalid, expired or revoked' })
    return
  }
  if (!apiRes.ok || typeof payload.token !== 'string' || !payload.token) {
    console.error(`[oauth] refresh-token returned ${apiRes.status}`)
    json(res, 503, { error: 'temporarily_unavailable', error_description: 'The WebAbility sign-in service returned an error.' })
    return
  }
  json(res, 200, {
    access_token: payload.token,
    token_type: 'Bearer',
    scope: 'mcp',
    ...(typeof payload.refreshToken === 'string' && payload.refreshToken ? { refresh_token: bindRefreshToken(payload.refreshToken, clientId!) } : {}),
  })
}

/** Route OAuth endpoints. Returns true when the request was handled here. */

export async function handleOAuth(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  sweep()
  const path = url.pathname

  if (
    req.method === 'GET' &&
    (path === '/.well-known/oauth-authorization-server' ||
      path === `/.well-known/oauth-authorization-server${MCP_PATH}` ||
      path === `/.well-known/oauth-authorization-server${SIGN_IN_MCP_PATH}`)
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
    json(res, 201, {
      client_id: mintClientId(uris, typeof body?.client_name === 'string' ? body.client_name : ''),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: uris,
      token_endpoint_auth_method: 'none',
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
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(`<!doctype html><meta charset="utf-8"><title>Invalid request</title><p style="font-family:sans-serif">Invalid authorization request: ${checked.error.replace(/</g, '&lt;')}</p>`)
      return true
    }
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
      json(res, 400, { error: checked.error })
      return true
    }
    try {
      const apiRes = await fetch(`${API_URL}/cli/device-code`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      if (!apiRes.ok) throw new Error(`device-code returned ${apiRes.status}`)
      const { deviceCode, userCode, verificationUrl } = (await apiRes.json()) as any
      if (!deviceCode || !verificationUrl) throw new Error('device-code response incomplete')
      const sid = randomBytes(16).toString('hex')
      const continueUrl = new URL(verificationUrl)
      continueUrl.searchParams.set('return_to', `${ISSUER}/authorize/complete?sid=${sid}`)
      continueUrl.searchParams.set('client', checked.params.client_label)
      sessions.set(sid, { ...checked.params, deviceCode, continueUrl: continueUrl.toString(), exp: Date.now() + SESSION_TTL_MS })
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
      messagePage(res, 400, 'Sign-in expired', 'This sign-in link has expired. Go back to the app and connect WebAbility again.')
      return true
    }
    let payload: any = {}
    let approved = false
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
      payload = (await apiRes.json().catch(() => ({}))) as any
      approved = apiRes.ok && typeof payload.token === 'string' && !!payload.token
    } catch (err) {
      console.error('[oauth] device-token request failed:', err)
      messagePage(res, 503, 'Sign-in service unavailable', 'Could not reach the WebAbility sign-in service. Reload this page in a moment.')
      return true
    }
    if (approved) {
      sessions.delete(sid)
      const code = b64url(randomBytes(32))
      codes.set(code, {
        token: payload.token,
        refresh_token: typeof payload.refreshToken === 'string' && payload.refreshToken ? payload.refreshToken : undefined,
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
    if (payload?.error === 'expired') {
      sessions.delete(sid)
      messagePage(res, 400, 'Sign-in expired', 'This sign-in link has expired. Go back to the app and connect WebAbility again.')
      return true
    }
    // Back button or a skipped consent click: send them to approve again.
    messagePage(res, 200, 'Not connected yet', 'You have not allowed access yet.', { href: session.continueUrl, label: 'Continue to WebAbility' })
    return true
  }

  if (path === '/token' && req.method === 'POST') {
    const p = await readParams(req)
    if (p.grant_type === 'refresh_token') {
      await refreshGrant(p.refresh_token, p.client_id, res)
      return true
    }
    if (p.grant_type !== 'authorization_code') {
      json(res, 400, { error: 'unsupported_grant_type' })
      return true
    }
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
    if (issued.redirect_uri !== p.redirect_uri || issued.client_id !== p.client_id) {
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
    json(res, 200, { access_token: issued.token, token_type: 'Bearer', scope: 'mcp', ...(issued.refresh_token ? { refresh_token: bindRefreshToken(issued.refresh_token, issued.client_id) } : {}) })
    return true
  }

  return false
}
