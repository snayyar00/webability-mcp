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
const USER_TOKEN = 'wa_live_test_token_abc123'
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
      const { deviceCode } = JSON.parse(body || '{}')
      const d = devices.get(deviceCode)
      if (!d) { res.statusCode = 400; res.end(JSON.stringify({ error: 'expired' })); return }
      // Real platform behavior (verified 2026-08-20): pending is HTTP 202 —
      // which fetch's res.ok treats as success — with an error body.
      if (!d.approved) { res.statusCode = 202; res.end(JSON.stringify({ error: 'authorization_pending' })); return }
      res.end(JSON.stringify({ token: USER_TOKEN }))
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
  // 1. auth challenges advertise the resource metadata. The server is
  // partial-auth (anonymous free tools are allowed), so the 401s are: a paid
  // tool called anonymously, and any request with a bad token.
  const paidAnon = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', id: 1, params: { name: 'start_audit', arguments: { url: 'https://example.com' } } }),
  })
  check('anonymous paid tool → 401', paidAnon.status === 401, paidAnon.status)
  const www = paidAnon.headers.get('www-authenticate') || ''
  check('401 carries WWW-Authenticate with resource_metadata', www.includes('resource_metadata="') && www.includes('/.well-known/oauth-protected-resource'), www)
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
    body: JSON.stringify({ redirect_uris: ['http://evil.example.com/cb'] }),
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
  const badRedirect = await fetch(`${as.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(reg.client_id)}&redirect_uri=${encodeURIComponent('https://evil.example.com/cb')}&state=s&code_challenge=${challenge}&code_challenge_method=S256`)
  check('authorize rejects unregistered redirect_uri', badRedirect.status === 400, badRedirect.status)

  // 6. device-flow session under the hood
  const startRes = await fetch(`${BASE}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: reg.client_id, redirect_uri: redirectUri, state: 'xyzstate',
      code_challenge: challenge, code_challenge_method: 'S256',
    }),
  })
  const start = await startRes.json().catch(() => ({}))
  check('authorize/start → 200 with session + verification url', startRes.status === 200 && !!start.sid && !!start.verificationUrl && !!start.userCode, JSON.stringify(start))

  const pending = await (await fetch(`${BASE}/authorize/poll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid: start.sid }) })).json()
  check('poll is pending before approval', pending.status === 'pending', JSON.stringify(pending))

  // user approves in the platform tab
  for (const d of devices.values()) d.approved = true

  let done
  for (let i = 0; i < 20; i++) {
    done = await (await fetch(`${BASE}/authorize/poll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid: start.sid }) })).json()
    if (done.status === 'complete') break
    await new Promise((r) => setTimeout(r, 250))
  }
  check('poll completes after approval', done && done.status === 'complete', JSON.stringify(done))
  const redirect = new URL(done.redirect)
  check('redirect goes to the registered redirect_uri', done.redirect.startsWith(redirectUri), done.redirect)
  check('redirect carries state', redirect.searchParams.get('state') === 'xyzstate')
  const code = redirect.searchParams.get('code')
  check('redirect carries a code', !!code && code.length > 10)

  // 7. token exchange (PKCE)
  const form = (o) => new URLSearchParams(o).toString()
  const badVerifier = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: b64url(randomBytes(32)) }),
  })
  check('token rejects wrong verifier', badVerifier.status === 400, badVerifier.status)

  const tokRes = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier }),
  })
  const tok = await tokRes.json().catch(() => ({}))
  check('token exchange → 200', tokRes.status === 200, `${tokRes.status} ${JSON.stringify(tok)}`)
  check('access_token is the user token', tok.access_token === USER_TOKEN)
  check('token_type Bearer', tok.token_type === 'Bearer')

  const reuse = await fetch(as.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier }),
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
