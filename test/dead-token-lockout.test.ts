/**
 * A stale token must never lock a real user out of the hosted server.
 * The case behind this file: a client config kept an expired
 * x-webability-token next to a good OAuth sign-in. The header won over OAuth,
 * each reconnect burned the bad-token budget, and the lockout then refused
 * the fresh sign-in too.
 *
 * Offline: real src/http.ts against a mock platform API.
 */
import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const LIMIT = 3
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback'
const VERIFIER = 'dead-token-lockout-verifier-0123456789abcdefghijklmnop'
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url')

const VALID = new Set(['good-a', 'good-after-burst', 'good-b', 'good-oauth', 'good-other', 'good-fallback', 'good-gateway', 'good-signed-in', 'good-refreshed', 'good-revoked'])
const whoamiSeen: string[] = []

/** An ephemeral port: a fixed range (24000-26000) collides with the same suite
 * in another checkout, and the health poll then talks to that other server. */
async function freePort(): Promise<number> {
  const probe = createServer()
  const listening = Promise.withResolvers<void>()
  probe.listen(0, '127.0.0.1', listening.resolve)
  await listening.promise
  const address = probe.address()
  assert.ok(address && typeof address === 'object')
  const closed = Promise.withResolvers<void>()
  probe.close(closed.resolve)
  await closed.promise
  return address.port
}

let api: Server
let child: ChildProcess
let BASE = ''

before(async () => {
  api = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/cli/whoami') {
        const token = (req.headers.authorization || '').replace('Bearer ', '')
        whoamiSeen.push(token)
        const answer = () => {
          res.statusCode = VALID.has(token) ? 200 : 401
          res.end('{}')
        }
        // Hold the verdict so every burst request is in flight before the first one lands.
        if (token === 'dead-burst') setTimeout(answer, 100)
        else answer()
      } else if (req.url?.startsWith('/cli/audit/')) {
        // The platform revokes this token: the account route refuses it, and
        // from now on so does /cli/whoami.
        const token = (req.headers.authorization || '').replace('Bearer ', '')
        if (token === 'good-revoked') VALID.delete(token)
        res.statusCode = VALID.has(token) ? 200 : 401
        res.end(VALID.has(token) ? JSON.stringify({ id: 1, status: 'done' }) : '{}')
      } else if (req.url === '/cli/device-code') {
        res.end(JSON.stringify({ deviceCode: 'dc', userCode: 'ABCD-1234', verificationUrl: 'https://app.webability.io/cli/verify?code=ABCD-1234' }))
      } else if (req.url === '/cli/device-token') {
        res.end(JSON.stringify({ token: 'good-signed-in', refreshToken: 'refresh-1' }))
      } else if (req.url === '/cli/refresh-token') {
        res.end(JSON.stringify({ token: 'good-refreshed', refreshToken: 'refresh-2' }))
      } else {
        res.statusCode = 404
        res.end('{}')
      }
    })
  })
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r))
  const apiPort = (api.address() as { port: number }).port
  const port = await freePort()
  BASE = `http://127.0.0.1:${port}`
  child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
    env: {
      ...process.env,
      PORT: String(port),
      WEBABILITY_API_URL: `http://127.0.0.1:${apiPort}`,
      MCP_PUBLIC_URL: BASE,
      OAUTH_SIGNING_SECRET: 'dead-token-test-secret-0123456789abcdef',
      TRUST_CF_CONNECTING_IP: 'true',
      BAD_TOKEN_PER_HOUR: String(LIMIT),
      ANON_AUTH_START_PER_HOUR: String(LIMIT),
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  })
  // 30 s, not 10: a tsx cold start on a loaded machine (parallel worktrees, CI)
  // can take many seconds before the child binds. A ready server answers on the
  // first poll, so the ceiling only bounds the failure path; stderr is inherited,
  // so a child that dies says why.
  for (let i = 0; i < 300; i++) {
    if (child.exitCode !== null) throw new Error(`server exited (${child.exitCode}) before listening`)
    try {
      await fetch(`${BASE}/health`)
      return
    } catch {
      await new Promise((r) => setTimeout(r, 100))
    }
  }
  throw new Error('server did not start within 30s')
})

after(() => {
  child?.kill()
  api?.close()
})

function listTools(ip: string, headers: Record<string, string> = {}) {
  return fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'cf-connecting-ip': ip, ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  })
}
const bearer = (t: string) => ({ authorization: `Bearer ${t}` })

/** Spend the whole bad-token budget of one IP with distinct garbage tokens. */
async function lockOut(ip: string) {
  for (let i = 0; i < LIMIT; i++) assert.equal((await listTools(ip, bearer(`${ip}-garbage-${i}`))).status, 401)
  assert.equal((await listTools(ip, bearer(`${ip}-garbage-over`))).status, 429)
}

/** The real sign-in: register, device flow, code exchange. Returns the /token JSON. */
async function signIn(ip: string): Promise<{ client_id: string; access_token: string; refresh_token: string }> {
  const reg = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'lockout', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
  })
  const { client_id } = (await reg.json()) as { client_id: string }
  const start = await fetch(`${BASE}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
    body: JSON.stringify({ client_id, redirect_uri: REDIRECT, state: 's', code_challenge: CHALLENGE, code_challenge_method: 'S256' }),
  })
  const { sid } = (await start.json()) as { sid: string }
  // /authorize/complete demands the HttpOnly binding cookie /authorize/start
  // just set (#228): a link alone cannot collect the code.
  const cookie = start.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
  const done = await fetch(`${BASE}/authorize/complete?sid=${sid}`, { redirect: 'manual', headers: { cookie } })
  const code = new URL(done.headers.get('location')!).searchParams.get('code')!
  const tok = await tokenGrant({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id, code_verifier: VERIFIER })
  return { client_id, ...tok }
}

async function tokenGrant(params: Record<string, string>) {
  const r = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  })
  assert.equal(r.status, 200)
  return (await r.json()) as { access_token: string; refresh_token: string }
}

test('a good OAuth token wins over a dead x-webability-token in the same request', async () => {
  const r = await listTools('198.51.100.1', { ...bearer('good-oauth'), 'x-webability-token': 'dead-static' })
  assert.equal(r.status, 200)
  assert.ok(!whoamiSeen.includes('dead-static'), 'the dead header must not be checked while Authorization is good')
})

test('x-webability-token alone still works (gateways that hide Authorization)', async () => {
  assert.equal((await listTools('198.51.100.2', { 'x-webability-token': 'good-other' })).status, 200)
})

test('one dead token repeated never locks the network out', async () => {
  const ip = '198.51.100.3'
  const before = whoamiSeen.filter((t) => t === 'dead-repeat').length
  for (let i = 0; i < LIMIT * 4; i++) {
    const r = await listTools(ip, bearer('dead-repeat'))
    assert.equal(r.status, 401, `attempt ${i + 1}`)
    assert.ok(r.headers.get('www-authenticate'), 'the 401 must let the client start sign-in')
  }
  assert.equal(whoamiSeen.filter((t) => t === 'dead-repeat').length - before, 1, 'one platform check per dead token')
  assert.equal((await listTools(ip, bearer('good-other'))).status, 200, 'a new valid token still works from this IP')
})

test('one dead token sent concurrently spends one unit of the budget', async () => {
  const ip = '198.51.100.10'
  const burst = await Promise.all(Array.from({ length: LIMIT * 3 }, () => listTools(ip, bearer('dead-burst'))))
  assert.ok(burst.every((r) => r.status === 401), burst.map((r) => r.status).join())
  assert.equal((await listTools(ip, bearer('good-after-burst'))).status, 200)
})

test('the other header is used once the Authorization token is known dead', async () => {
  const ip = '198.51.100.4'
  const headers = { ...bearer('dead-auth'), 'x-webability-token': 'good-fallback' }
  assert.equal((await listTools(ip, headers)).status, 401)
  assert.equal((await listTools(ip, headers)).status, 200)
})

test('during a lockout a verified x-webability-token beats an unknown Authorization token', async () => {
  const ip = '198.51.100.9'
  assert.equal((await listTools(ip, { 'x-webability-token': 'good-gateway' })).status, 200)
  await lockOut(ip)
  const r = await listTools(ip, { ...bearer('gateway-hop-token'), 'x-webability-token': 'good-gateway' })
  assert.equal(r.status, 200)
})

test('during a lockout a known dead token still gets 401, so the client can sign in again', async () => {
  const ip = '198.51.100.5'
  // The dead token spends one unit of the budget, so garbage spends the rest.
  assert.equal((await listTools(ip, bearer('dead-before-lockout'))).status, 401)
  for (let i = 1; i < LIMIT; i++) assert.equal((await listTools(ip, bearer(`${ip}-garbage-${i}`))).status, 401)
  assert.equal((await listTools(ip, bearer(`${ip}-garbage-over`))).status, 429)
  const r = await listTools(ip, bearer('dead-before-lockout'))
  assert.equal(r.status, 401)
  assert.ok(r.headers.get('www-authenticate'))
})

test('the lockout still stops a garbage flood: 429, no platform call, and the text names both headers', async () => {
  const ip = '198.51.100.6'
  await lockOut(ip)
  const seen = whoamiSeen.length
  const r = await listTools(ip, bearer('garbage-after-lockout'))
  assert.equal(r.status, 429)
  assert.ok(r.headers.get('retry-after'))
  assert.equal(whoamiSeen.length, seen)
  const body = (await r.json()) as { error: { message: string } }
  assert.match(body.error.message, /x-webability-token/)
})

test('a fresh OAuth sign-in works from a locked-out IP', async () => {
  const ip = '198.51.100.7'
  await lockOut(ip)
  const { access_token } = await signIn(ip)
  assert.equal(access_token, 'good-signed-in')
  assert.equal((await listTools(ip, bearer(access_token))).status, 200)
})

test('a refreshed OAuth token works from a locked-out IP', async () => {
  const ip = '198.51.100.8'
  const { client_id, refresh_token } = await signIn(ip)
  await lockOut(ip)
  const fresh = await tokenGrant({ grant_type: 'refresh_token', refresh_token, client_id })
  assert.equal(fresh.access_token, 'good-refreshed')
  assert.equal((await listTools(ip, bearer(fresh.access_token))).status, 200)
})

test('Authorization wins over another account\'s cached token in x-webability-token', async () => {
  // B's token is cached by an earlier request, so the cache alone cannot tell
  // whose request this is. A stale header pasted into a client config must not
  // run the call as B for the next TOKEN_TTL_MS.
  assert.equal((await listTools('198.51.100.12', bearer('good-b'))).status, 200)
  const before = whoamiSeen.filter((t) => t === 'good-a').length
  const r = await listTools('198.51.100.11', { ...bearer('good-a'), 'x-webability-token': 'good-b' })
  assert.equal(r.status, 200)
  assert.equal(whoamiSeen.filter((t) => t === 'good-a').length - before, 1, 'the Authorization token is the one verified, so the call runs on that account')
})

test('the /authorize/start flood limit carries a sign-in challenge, not just a bare 429', async () => {
  // A client that only starts OAuth from a challenge (claude.ai, Cursor, VS
  // Code) has nothing to act on in a bare 429, and the sign-in it is already
  // trying to start is exactly what the limit refused.
  const ip = '198.51.100.13'
  const start = () =>
    fetch(`${BASE}/authorize/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
      body: JSON.stringify({ client_id: 'x.y', redirect_uri: REDIRECT, code_challenge: CHALLENGE }),
    })
  for (let i = 0; i < LIMIT; i++) await start()
  const r = await start()
  assert.equal(r.status, 429)
  assert.ok(r.headers.get('retry-after'))
  const challenge = r.headers.get('www-authenticate') || ''
  assert.match(challenge, /resource_metadata="[^"]+"/)
  assert.doesNotMatch(challenge, /invalid_token/, 'this caller sent no token')
})

test('a token the platform refuses on a tool call is not trusted by the HTTP gate for the cache TTL', async () => {
  const ip = '203.0.113.77'
  // Validated once: the gate caches it.
  assert.equal((await listTools(ip, bearer('good-revoked'))).status, 200)
  // A tool call reaches the platform, which now refuses the token.
  const call = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'cf-connecting-ip': ip, ...bearer('good-revoked') },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'get_audit', arguments: { id: 1 } } }),
  })
  await call.body?.cancel()
  // The very next request re-validates and is refused, not served from the cache.
  assert.equal((await listTools(ip, bearer('good-revoked'))).status, 401, 'the gate must share the cache the tool call evicted')
})
