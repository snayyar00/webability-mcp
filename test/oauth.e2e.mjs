#!/usr/bin/env node
/**
 * E2E test for the OAuth 2.1 layer on the hosted (Streamable HTTP) server.
 *
 * Claude's connector directory connects via: protected-resource metadata →
 * AS metadata → dynamic client registration → /authorize (which drives the
 * platform device-code flow) → /token (PKCE). This test runs the real HTTP
 * entry (tsx src/http.ts) against a mock platform API and walks that exact
 * sequence, plus the failure paths that matter (bad verifier, code reuse,
 * bad redirect_uri).
 *
 * Fully offline. Run: node test/oauth.e2e.mjs   (from packages/mcp)
 */
import { createServer } from 'http'
import { spawn } from 'child_process'
import { createHash, randomBytes } from 'crypto'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))

let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + String(detail)}`)
  if (!cond) failures++
}

// --- mock platform API (device-code flow + whoami) --------------------------
// Approval is simulated: a device code becomes "approved" once the test calls
// approve(). Until then /cli/device-token returns authorization_pending.
const devices = new Map() // deviceCode -> { approved: boolean }
// When set, /cli/device-token answers with this HTTP status (rate limit / outage).
let deviceTokenFailStatus = 0
const USER_TOKEN = 'wa_live_test_token_abc123'
const REFRESH_TOKEN = 'wa_refresh_test_token_r1'
const USER_TOKEN_2 = 'wa_live_test_token_rotated'
const REFRESH_TOKEN_2 = 'wa_refresh_test_token_r2'
const mockApi = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json')
    if (req.url === '/cli/device-code' && req.method === 'POST') {
      const deviceCode = 'dev-' + randomBytes(8).toString('hex')
      devices.set(deviceCode, { approved: false })
      res.end(JSON.stringify({
        deviceCode,
        userCode: 'ABCD-1234',
        verificationUrl: 'https://app.webability.io/activate?code=ABCD-1234',
        expiresIn: 300,
      }))
      return
    }
    if (req.url === '/cli/device-token' && req.method === 'POST') {
      if (deviceTokenFailStatus) { res.statusCode = deviceTokenFailStatus; res.end(JSON.stringify({ error: 'Too many requests' })); return }
      const { deviceCode } = JSON.parse(body || '{}')
      const d = devices.get(deviceCode)
      if (!d) { res.statusCode = 400; res.end(JSON.stringify({ error: 'expired' })); return }
      // Real platform behavior (verified 2026-08-20): pending is HTTP 202 —
      // which fetch's res.ok treats as success — with an error body.
      if (!d.approved) { res.statusCode = 202; res.end(JSON.stringify({ error: 'authorization_pending' })); return }
      res.end(JSON.stringify({ token: USER_TOKEN, refreshToken: REFRESH_TOKEN }))
      return
    }
    if (req.url === '/cli/refresh-token' && req.method === 'POST') {
      const { refreshToken } = JSON.parse(body || '{}')
      if (refreshToken !== REFRESH_TOKEN && refreshToken !== REFRESH_TOKEN_2) { res.statusCode = 401; res.end(JSON.stringify({ error: 'invalid_grant' })); return }
      res.end(JSON.stringify({ token: USER_TOKEN_2, refreshToken: REFRESH_TOKEN_2 }))
      return
    }
    if (req.url === '/cli/whoami') {
      const auth = req.headers.authorization || ''
      res.statusCode = auth === `Bearer ${USER_TOKEN}` ? 200 : 401
      res.end(JSON.stringify({}))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
})
await new Promise((r) => mockApi.listen(0, '127.0.0.1', r))
const apiPort = mockApi.address().port

// --- boot the real HTTP server ----------------------------------------------
const PORT = 18000 + Math.floor(Math.random() * 2000)
const BASE = `http://127.0.0.1:${PORT}`
const child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
  env: {
    ...process.env,
    PORT: String(PORT),
    WEBABILITY_API_URL: `http://127.0.0.1:${apiPort}`,
    MCP_PUBLIC_URL: BASE,
    OAUTH_SIGNING_SECRET: 'test-signing-secret-0123456789abcdef',
  },
  stdio: ['ignore', 'inherit', 'inherit'],
})
// wait for it to listen
for (let i = 0; i < 50; i++) {
  try { await fetch(`${BASE}/health`); break } catch { await new Promise((r) => setTimeout(r, 200)) }
}

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

try {
  // 1. auth challenges advertise the resource metadata. /mcp is partial-auth
  // (anonymous free tools are allowed, and an anonymous account tool gets an
  // isError tool result, not a 401), so the 401s are: any request to the
  // sign-in path /mcp/auth without a token, and any request with a bad token.
  const signInAnon = await fetch(`${BASE}/mcp/auth`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1, params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } } }),
  })
  check('anonymous request to /mcp/auth → 401', signInAnon.status === 401, signInAnon.status)
  const www = signInAnon.headers.get('www-authenticate') || ''
  check('401 carries WWW-Authenticate with resource_metadata', www.includes('resource_metadata="') && www.includes('/.well-known/oauth-protected-resource/mcp/auth'), www)
  const badTok = await fetch(`${BASE}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer bogus' }, body: '{}' })
  check('garbage token → 401 (not silent anonymous downgrade)', badTok.status === 401, badTok.status)

  // 2. protected-resource metadata (bare + path-suffixed)
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const r = await fetch(BASE + p)
    const j = await r.json().catch(() => ({}))
    check(`${p} → 200`, r.status === 200, r.status)
    check(`${p} names this AS`, Array.isArray(j.authorization_servers) && j.authorization_servers[0] === BASE, JSON.stringify(j))
    check(`${p} resource is the mcp endpoint`, j.resource === `${BASE}/mcp`, j.resource)
  }

  // 3. AS metadata
  const asRes = await fetch(`${BASE}/.well-known/oauth-authorization-server`)
  const as = await asRes.json().catch(() => ({}))
  check('AS metadata → 200', asRes.status === 200, asRes.status)
  check('AS issuer', as.issuer === BASE, as.issuer)
  check('AS has endpoints', !!as.authorization_endpoint && !!as.token_endpoint && !!as.registration_endpoint, JSON.stringify(as))
  check('AS supports S256', (as.code_challenge_methods_supported || []).includes('S256'))
  check('AS auth method none', (as.token_endpoint_auth_methods_supported || []).includes('none'))
  check('AS auth method client_secret_basic', (as.token_endpoint_auth_methods_supported || []).includes('client_secret_basic'))
  check('AS auth method client_secret_post', (as.token_endpoint_auth_methods_supported || []).includes('client_secret_post'))

  // 4. dynamic client registration
  const redirectUri = 'https://claude.ai/api/mcp/auth_callback'
  const regRes = await fetch(as.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Claude', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' }),
  })
  const reg = await regRes.json().catch(() => ({}))
  check('DCR → 201', regRes.status === 201, `${regRes.status} ${JSON.stringify(reg)}`)
  check('DCR returns client_id', typeof reg.client_id === 'string' && reg.client_id.length > 10)
  check('DCR echoes redirect_uris', JSON.stringify(reg.redirect_uris) === JSON.stringify([redirectUri]))

  const regBad = await fetch(as.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://attacker.invalid/cb'] }),
  })
  check('DCR rejects non-https non-localhost redirect', regBad.status === 400, regBad.status)

  // 5. authorize page
  const verifier = b64url(randomBytes(32))
  const challenge = b64url(createHash('sha256').update(verifier).digest())
  const authUrl = `${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(reg.client_id)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=xyzstate&code_challenge=${challenge}&code_challenge_method=S256`
  const page = await fetch(authUrl)
  const pageHtml = await page.text()
  check('authorize page → 200 html', page.status === 200 && (page.headers.get('content-type') || '').includes('text/html'), page.status)
  check('authorize page names the requesting client', pageHtml.includes('"client_label":"Claude (claude.ai)"'), pageHtml.slice(0, 200))

  const badClient = await fetch(authUrl.replace(encodeURIComponent(reg.client_id), 'forged-client-id'))
  check('authorize rejects unknown client_id', badClient.status === 400, badClient.status)
  const badRedirect = await fetch(`${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(reg.client_id)}&redirect_uri=${encodeURIComponent('https://attacker.invalid/cb')}&state=s&code_challenge=${challenge}&code_challenge_method=S256`)
  check('authorize rejects unregistered redirect_uri', badRedirect.status === 400, badRedirect.status)

  // 6. device-flow session under the hood
  // A browser replays its cookie jar to every request on this origin, and each
  // /authorize/start appends its binding to the one cookie (#228).
  let jar = ''
  const keepCookies = (setCookies) => {
    for (const header of setCookies) {
      const pair = header.split(';')[0]
      const name = pair.split('=')[0]
      jar = [...jar.split('; ').filter((p) => p && p.split('=')[0] !== name), pair].join('; ')
    }
  }
  const startSignIn = async (body) => {
    const res = await fetch(`${BASE}/authorize/start`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: jar }, body: JSON.stringify(body) })
    const setCookies = res.headers.getSetCookie()
    keepCookies(setCookies)
    return { res, json: await res.json().catch(() => ({})) }
  }

  const startCall = await startSignIn({
    client_id: reg.client_id, redirect_uri: redirectUri, state: 'xyzstate',
    code_challenge: challenge, code_challenge_method: 'S256',
  })
  const startRes = startCall.res
  const start = startCall.json
  check('authorize/start → 200 with session + continue url', startRes.status === 200 && !!start.sid && !!start.continueUrl && !!start.userCode, JSON.stringify(start))
  // The browser binding (#228): an HttpOnly cookie, never part of a URL.
  const setCookie = startRes.headers.getSetCookie().join('; ')
  check('authorize/start sets an HttpOnly SameSite=Lax binding cookie', setCookie.includes('HttpOnly') && setCookie.includes('SameSite=Lax') && setCookie.includes('Path=/authorize'), setCookie)
  const binding = jar.split('=')[1].split('.')[1]
  // The sid is a handle; the binding is the secret, and it stays in the cookie.
  check('the binding secret never appears in the continue url', !start.continueUrl.includes(binding), start.continueUrl)
  const cont = new URL(start.continueUrl)
  const returnTo = cont.searchParams.get('return_to') || ''
  check('continue url is the platform consent page with the user code', cont.origin === 'https://app.webability.io' && cont.searchParams.get('code') === 'ABCD-1234', start.continueUrl)
  check('continue url returns to /authorize/complete for this session', returnTo === `${BASE}/authorize/complete?sid=${start.sid}`, returnTo)
  check('continue url names the client for the consent screen', cont.searchParams.get('client') === 'Claude (claude.ai)', cont.searchParams.get('client'))

  // The platform page sends the user back to return_to after consent.
  const complete = async (sid, withCookie = jar) => {
    const res = await fetch(`${BASE}/authorize/complete?sid=${encodeURIComponent(sid)}`, { redirect: 'manual', headers: { cookie: withCookie } })
    // Success and expiry both rewrite the cookie (a spent sid is dropped).
    if (withCookie === jar) keepCookies(res.headers.getSetCookie())
    return res
  }
  const stolen = await complete(start.sid, '')
  check('a session link in another browser cannot collect the code', stolen.status === 400 && (await stolen.text()).includes('same browser'), stolen.status)
  const pending = await complete(start.sid)
  const pendingHtml = await pending.text()
  check('complete before approval → 200 page linking back to consent', pending.status === 200 && pendingHtml.includes('Not connected yet') && pendingHtml.includes('return_to='), `${pending.status} ${pendingHtml.slice(0, 200)}`)
  const unknown = await complete('nope')
  check('complete with an unknown session → 400 expired page', unknown.status === 400 && (await unknown.text()).includes('expired'), unknown.status)

  // user approves on the platform consent page
  for (const d of devices.values()) d.approved = true

  // A platform rate limit or outage at return time is not "not approved":
  // show a reload page and keep the session so the reload completes.
  for (const status of [429, 500, 503]) {
    deviceTokenFailStatus = status
    const busy = await complete(start.sid)
    const busyHtml = await busy.text()
    check(`complete when the platform answers ${status} → 503 reload page`, busy.status === 503 && busyHtml.includes('Reload') && !busyHtml.includes('Not connected yet'), `${busy.status} ${busyHtml.slice(0, 160)}`)
  }
  deviceTokenFailStatus = 0

  const done = await complete(start.sid)
  const location = done.headers.get('location') || ''
  check('complete after approval → 302 to the client', done.status === 302, done.status)
  const redirect = new URL(location)
  check('redirect goes to the registered redirect_uri', location.startsWith(redirectUri), location)
  check('redirect carries state', redirect.searchParams.get('state') === 'xyzstate')
  const code = redirect.searchParams.get('code')
  check('redirect carries a code', !!code && code.length > 10)
  const replay = await complete(start.sid)
  check('a used session cannot complete twice', replay.status === 400, replay.status)

  // 7. token exchange (PKCE)
  const form = (o) => new URLSearchParams(o).toString()
  const badVerifier = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: b64url(randomBytes(32)) }),
  })
  check('token rejects wrong verifier', badVerifier.status === 400, badVerifier.status)
  // Codes are burned on the first redemption attempt, even a failed one.
  const afterBad = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier }),
  })
  check('wrong-verifier attempt burns the code', afterBad.status === 400, afterBad.status)

  // A fresh sign-in for the real exchange.
  const start2 = (await startSignIn({
    client_id: reg.client_id, redirect_uri: redirectUri, state: 'xyzstate2', code_challenge: challenge, code_challenge_method: 'S256',
  })).json
  for (const d of devices.values()) d.approved = true
  const done2 = await complete(start2.sid)
  const code2 = new URL(done2.headers.get('location')).searchParams.get('code')
  check('second sign-in yields a fresh code', !!code2 && code2 !== code)

  const tokRes = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code: code2, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier }),
  })
  const tok = await tokRes.json().catch(() => ({}))
  check('token exchange → 200', tokRes.status === 200, `${tokRes.status} ${JSON.stringify(tok)}`)
  check('access_token is the user token', tok.access_token === USER_TOKEN)
  check('token_type Bearer', tok.token_type === 'Bearer')
  check('token exchange returns a refresh token', typeof tok.refresh_token === 'string' && tok.refresh_token.length > 0, JSON.stringify(tok))
  check('refresh token is bound to the client, not the raw platform token', tok.refresh_token !== REFRESH_TOKEN, tok.refresh_token)
  check('AS advertises refresh_token grant', (as.grant_types_supported || []).includes('refresh_token'), JSON.stringify(as.grant_types_supported))

  // 7b. refresh grant (Zapier and other long-lived clients)
  const tokenPost = (o) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form(o) })
  const reg2 = await (await fetch(as.registration_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['https://other.example.org/cb'], client_name: 'Other' }),
  })).json()
  const refOther = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: reg2.client_id }))
  const refOtherJson = await refOther.json()
  check('refresh via another client → 400 invalid_grant', refOther.status === 400 && refOtherJson.error === 'invalid_grant', `${refOther.status} ${JSON.stringify(refOtherJson)}`)
  const refNoClient = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: tok.refresh_token }))
  const refNoClientJson = await refNoClient.json()
  check('refresh without client_id → 400 invalid_grant', refNoClient.status === 400 && refNoClientJson.error === 'invalid_grant', `${refNoClient.status} ${JSON.stringify(refNoClientJson)}`)
  const refRaw = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: REFRESH_TOKEN, client_id: reg.client_id }))
  const refRawJson = await refRaw.json()
  check('raw platform refresh token → 400 invalid_grant', refRaw.status === 400 && refRawJson.error === 'invalid_grant', `${refRaw.status} ${JSON.stringify(refRawJson)}`)
  const refRes = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: reg.client_id }))
  const ref = await refRes.json()
  check('refresh grant → 200', refRes.status === 200, `${refRes.status} ${JSON.stringify(ref)}`)
  check('refresh grant returns the new access token', ref.access_token === USER_TOKEN_2, JSON.stringify(ref))
  check('refresh grant rotates the refresh token', typeof ref.refresh_token === 'string' && ref.refresh_token !== tok.refresh_token && ref.refresh_token !== REFRESH_TOKEN_2, JSON.stringify(ref))
  check('refresh grant token_type Bearer', ref.token_type === 'Bearer')
  const refAgain = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: ref.refresh_token, client_id: reg.client_id }))
  check('rotated refresh token works again for the same client', refAgain.status === 200, refAgain.status)
  const refBad = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token', refresh_token: 'nope', client_id: reg.client_id }))
  const refBadJson = await refBad.json()
  check('bad refresh token → 400 invalid_grant', refBad.status === 400 && refBadJson.error === 'invalid_grant', `${refBad.status} ${JSON.stringify(refBadJson)}`)
  const refMissing = await fetch(as.token_endpoint, tokenPost({ grant_type: 'refresh_token' }))
  const refMissingJson = await refMissing.json()
  check('missing refresh token → 400 invalid_request', refMissing.status === 400 && refMissingJson.error === 'invalid_request', `${refMissing.status} ${JSON.stringify(refMissingJson)}`)

  // 7c. confidential clients (RFC 6749 §2.3.1): GoHighLevel Agent Studio and
  // other strict clients register with client_secret_basic and send client_id
  // only in the Authorization header. The secret is never checked — PKCE is
  // the proof — but registration must echo the method and return a secret.
  const confReg = await (await fetch(as.registration_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['https://studio.gohighlevel.com/mcp/oauth/callback'], client_name: 'GoHighLevel', token_endpoint_auth_method: 'client_secret_basic' }),
  })).json()
  check('DCR echoes client_secret_basic', confReg.token_endpoint_auth_method === 'client_secret_basic', JSON.stringify(confReg))
  check('DCR returns a client_secret for a confidential client', typeof confReg.client_secret === 'string' && confReg.client_secret.length > 10, JSON.stringify(confReg))
  const confRedirect = 'https://studio.gohighlevel.com/mcp/oauth/callback'
  const basicHeader = (id, secret) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`
  const confStart = (await startSignIn({ client_id: confReg.client_id, redirect_uri: confRedirect, state: 'conf', code_challenge: challenge, code_challenge_method: 'S256' })).json
  for (const d of devices.values()) d.approved = true
  const confDone = await complete(confStart.sid)
  const confCode = new URL(confDone.headers.get('location')).searchParams.get('code')
  check('confidential client sign-in yields a code', !!confCode, confDone.status)

  const confTokRes = await fetch(as.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basicHeader(confReg.client_id, confReg.client_secret) },
    body: form({ grant_type: 'authorization_code', code: confCode, redirect_uri: confRedirect, code_verifier: verifier }),
  })
  const confTok = await confTokRes.json().catch(() => ({}))
  check('token with client_id only in the Basic header → 200', confTokRes.status === 200, `${confTokRes.status} ${JSON.stringify(confTok)}`)
  check('Basic-header exchange returns the user token', confTok.access_token === USER_TOKEN, JSON.stringify(confTok))
  check('Basic-header exchange returns a refresh token', typeof confTok.refresh_token === 'string' && confTok.refresh_token.length > 0, JSON.stringify(confTok))

  const confRefRes = await fetch(as.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basicHeader(confReg.client_id, confReg.client_secret) },
    body: form({ grant_type: 'refresh_token', refresh_token: confTok.refresh_token }),
  })
  const confRef = await confRefRes.json().catch(() => ({}))
  check('refresh with client_id only in the Basic header → 200', confRefRes.status === 200, `${confRefRes.status} ${JSON.stringify(confRef)}`)
  check('Basic-header refresh returns the rotated token', confRef.access_token === USER_TOKEN_2, JSON.stringify(confRef))

  const confMismatch = await fetch(as.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basicHeader(confReg.client_id, confReg.client_secret) },
    body: form({ grant_type: 'refresh_token', refresh_token: confRef.refresh_token, client_id: reg.client_id }),
  })
  const confMismatchJson = await confMismatch.json().catch(() => ({}))
  check('body client_id that conflicts with the Basic header → 400 invalid_grant', confMismatch.status === 400 && confMismatchJson.error === 'invalid_grant', `${confMismatch.status} ${JSON.stringify(confMismatchJson)}`)

  const reuse = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code: code2, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier }),
  })
  check('code is single-use', reuse.status === 400, reuse.status)

  // 8. hardening: non-string JSON params must 400, not crash the handler
  const objParams = await fetch(`${BASE}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: {}, redirect_uri: ['x'], code_challenge: 5 }),
  })
  check('authorize/start rejects non-string params with 400', objParams.status === 400, objParams.status)
  const alive = await fetch(`${BASE}/health`)
  check('server still healthy after malformed params', alive.status === 200, alive.status)

  // 9. loopback redirects may vary the port (RFC 8252), non-loopback may not
  const loopReg = await (await fetch(as.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://127.0.0.1:33418/callback'] }),
  })).json()
  const loopAuth = await fetch(`${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(loopReg.client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:41999/callback')}&state=s&code_challenge=${challenge}&code_challenge_method=S256`)
  check('loopback redirect with a different port is accepted', loopAuth.status === 200, loopAuth.status)
  const loopBadPath = await fetch(`${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(loopReg.client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:41999/other')}&state=s&code_challenge=${challenge}&code_challenge_method=S256`)
  check('loopback redirect with a different path is rejected', loopBadPath.status === 400, loopBadPath.status)
  const httpsPortShift = await fetch(`${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(reg.client_id)}&redirect_uri=${encodeURIComponent(redirectUri.replace('claude.ai', 'claude.ai:8443'))}&state=s&code_challenge=${challenge}&code_challenge_method=S256`)
  check('non-loopback redirect with a different port is rejected', httpsPortShift.status === 400, httpsPortShift.status)

  // 10. the issued token opens /mcp
  const authed = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tok.access_token}` },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1, params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'oauth-e2e', version: '0.0.0' } } }),
  })
  check('issued token opens /mcp (initialize succeeds)', authed.status === 200, authed.status)
} finally {
  child.kill()
  mockApi.close()
}

console.log(failures ? `\n${failures} FAILED` : '\nALL PASS')
process.exit(failures ? 1 : 0)
