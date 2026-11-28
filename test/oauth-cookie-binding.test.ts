/**
 * #228: /authorize/complete used to be the only thing tying an approval to a
 * browser, and the sid in return_to was the whole of it — so whoever minted
 * the sid could collect the code for a client of their choosing (the consent
 * screen names the client, but the victim is already clicking "allow").
 *
 * Now /authorize/start also sets a random HttpOnly binding cookie and
 * /authorize/complete demands it back. The sid stays in return_to as a
 * non-secret handle, and the limiter on complete is charged only after the
 * session and the cookie both check out.
 *
 * Offline: real src/http.ts against a mock platform API.
 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { createServer as createPort, type AddressInfo } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'

const REDIRECT = 'https://claude.ai/api/mcp/auth_callback'
const VERIFIER = 'cookie-binding-verifier-0123456789abcdefghijklmnop'
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url')
const SIGNING_SECRET = 'cookie-binding-test-secret-0123456789abcdef'

let approved = false
let deviceCodes = 0
const children: ChildProcess[] = []

// --- the mock platform API --------------------------------------------------

/** One string field of a JSON body. Our own mock's bodies, but they arrive as
 * `unknown` — narrow, never cast. */
function stringField(value: unknown, field: string): string {
  if (!value || typeof value !== 'object' || !(field in value)) assert.fail(`missing ${field} in ${JSON.stringify(value)}`)
  const found = Object.fromEntries(Object.entries(value))[field]
  if (typeof found !== 'string') assert.fail(`${field} is not a string: ${JSON.stringify(value)}`)
  return found
}

function mockPlatform(): Server {
  return createServer((req, res) => {
    let raw = ''
    req.on('data', (chunk: Buffer) => (raw += chunk.toString()))
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/cli/device-code') {
        deviceCodes += 1
        res.end(JSON.stringify({ deviceCode: `dc-${deviceCodes}`, userCode: 'ABCD-1234', verificationUrl: 'https://app.webability.io/cli/verify?code=ABCD-1234' }))
        return
      }
      if (req.url === '/cli/device-token') {
        if (!approved) {
          res.statusCode = 202
          res.end(JSON.stringify({ error: 'authorization_pending' }))
          return
        }
        const deviceCode = stringField(raw ? JSON.parse(raw) : {}, 'deviceCode')
        res.end(JSON.stringify({ token: `user-token-${deviceCode}`, refreshToken: `refresh-${deviceCode}` }))
        return
      }
      // /cli/whoami answers 200: a token minted here is a valid token.
      res.end('{}')
    })
  })
}

const api = mockPlatform()
const apiListening = Promise.withResolvers<void>()
api.listen(0, '127.0.0.1', apiListening.resolve)
await apiListening.promise
const apiUrl = `http://127.0.0.1:${portOf(api)}`

after(() => {
  for (const child of children) child.kill()
  api.close()
})

// --- the server under test --------------------------------------------------

/** The port any listening server bound to (http or net). */
function portOf(listener: { address(): string | AddressInfo | null }): number {
  const address = listener.address()
  assert.ok(address && typeof address === 'object', 'server is not listening on a socket')
  return address.port
}

async function freePort(): Promise<number> {
  const probe = createPort()
  const listening = Promise.withResolvers<void>()
  probe.listen(0, listening.resolve)
  await listening.promise
  const port = portOf(probe)
  const closed = Promise.withResolvers<void>()
  probe.close(closed.resolve)
  await closed.promise
  return port
}

/** A real hosted server against the mock platform. The readiness loop needs
 * real time: it waits on another process binding a socket. */
async function startServer(env: Record<string, string> = {}): Promise<string> {
  const port = await freePort()
  const base = `http://127.0.0.1:${port}`
  const child = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: {
      ...process.env,
      PORT: String(port),
      WEBABILITY_API_URL: apiUrl,
      MCP_PUBLIC_URL: base,
      OAUTH_SIGNING_SECRET: SIGNING_SECRET,
      TRUSTED_PROXY_HOPS: '0',
      WEBABILITY_SCAN_TELEMETRY: 'off',
      POSTHOG_PROJECT_API_KEY: '',
      POSTHOG_API_KEY: '',
      ...env,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  children.push(child)
  // The child's own reason (a lost port race, a boot guard) is the only way to
  // tell a slow start from a dead one; the port came from a closed probe socket,
  // so another suite can still grab it in between.
  let stderr = ''
  child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()))
  // 30 s, not 10: a tsx cold start under a loaded machine (parallel worktrees,
  // CI) can take several seconds before the child binds. A ready server
  // answers on the first poll, so the ceiling only bounds the failure path.
  for (let i = 0; i < 300; i++) {
    if (child.exitCode !== null) throw new Error(`server exited (${child.exitCode}) before listening: ${stderr.trim() || 'no stderr'}`)
    try {
      if ((await fetch(`${base}/health`)).ok) return base
    } catch {
      // not up yet
    }
    await sleep(100)
  }
  throw new Error(`server did not start on ${base} within 30s: ${stderr.trim() || 'no stderr'}`)
}

const base = await startServer()

interface Started {
  sid: string
  /** The raw Set-Cookie attributes, for the attribute assertions. */
  setCookie: string
  /** Every `sid.binding` pair the cookie carries. */
  pairs: string[]
  /** This session's own pair. */
  pair: string
}

async function register(server = base): Promise<string> {
  const res = await fetch(`${server}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Cookie Test', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
  })
  assert.equal(res.status, 201, 'registration must succeed')
  return stringField(await res.json(), 'client_id')
}

async function startSession(clientId: string, cookie = '', server = base): Promise<Started> {
  const res = await fetch(`${server}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify({ client_id: clientId, redirect_uri: REDIRECT, state: 's', code_challenge: CHALLENGE, code_challenge_method: 'S256' }),
  })
  assert.equal(res.status, 200)
  const sid = stringField(await res.json(), 'sid')
  const setCookies = res.headers.getSetCookie()
  const value = (setCookies[0] ?? '').split(';')[0].split('=')[1] ?? ''
  const pairs = value.split('~').filter(Boolean)
  const pair = pairs.find((p) => p.startsWith(`${sid}.`))
  assert.ok(pair, `cookie "${value}" does not carry sid ${sid}`)
  return { sid, setCookie: setCookies.join('; '), pairs, pair }
}

const cookieHeader = (pairs: string[]) => `wa_oauth=${pairs.join('~')}`

const complete = (sid: string, cookie?: string, server = base) =>
  fetch(`${server}/authorize/complete?sid=${sid}`, { redirect: 'manual', ...(cookie ? { headers: { cookie } } : {}) })

// --- the tests --------------------------------------------------------------

test('authorize/start sets an HttpOnly SameSite=Lax cookie scoped to /authorize', async () => {
  const session = await startSession(await register())
  assert.match(session.setCookie, /HttpOnly/, session.setCookie)
  // Lax, not Strict: the user arrives back from app.webability.io on a
  // top-level navigation, and Strict would drop the cookie there.
  assert.match(session.setCookie, /SameSite=Lax/, session.setCookie)
  assert.match(session.setCookie, /Path=\/authorize/, session.setCookie)
  assert.match(session.setCookie, /Max-Age=\d+/, session.setCookie)
  assert.match(session.pair, new RegExp(`^${session.sid}\\.[0-9a-f]{32}$`))
})

test('the binding secret never reaches the continue url', async () => {
  const res = await fetch(`${base}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: await register(),
      redirect_uri: REDIRECT,
      state: 's',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
    }),
  })
  assert.equal(res.status, 200)
  const body: unknown = await res.json()
  const sid = stringField(body, 'sid')
  const continueUrl = stringField(body, 'continueUrl')
  const binding = (res.headers.getSetCookie()[0] ?? '').split(';')[0].split('=')[1].split('~').pop()?.split('.')[1] ?? ''
  assert.match(binding, /^[0-9a-f]{32}$/)
  assert.ok(!continueUrl.includes(binding), 'the binding must travel only in the cookie')
  // The sid is only a handle: it may appear (the platform has to come back to it).
  assert.ok(continueUrl.includes(sid), continueUrl)
})

test('a session link without the cookie cannot collect a code', async () => {
  const session = await startSession(await register())
  approved = true
  const res = await complete(session.sid)
  assert.equal(res.status, 400)
  assert.equal(res.headers.get('location'), null, 'no redirect, so no code leaves')
  assert.match(await res.text(), /same browser/)
})

test("another session's cookie does not unlock this session, and this one still can", async () => {
  const clientId = await register()
  const first = await startSession(clientId)
  const second = await startSession(clientId, cookieHeader(first.pairs))
  assert.deepEqual(second.pairs.slice(-2), [first.pair, second.pair], 'both tabs stay bound')

  const wrong = await complete(first.sid, cookieHeader([second.pair]))
  assert.equal(wrong.status, 400)
  assert.equal(wrong.headers.get('location'), null)

  // The refusal must not have destroyed the real session.
  const right = await complete(first.sid, cookieHeader(second.pairs))
  assert.equal(right.status, 302)
  const location = right.headers.get('location') ?? ''
  assert.ok(new URL(location).searchParams.get('code'), location)
})

test('the completed session is dropped from the cookie, the other tab keeps its entry', async () => {
  const clientId = await register()
  const first = await startSession(clientId)
  const second = await startSession(clientId, cookieHeader(first.pairs))
  const res = await complete(first.sid, cookieHeader(second.pairs))
  assert.equal(res.status, 302)
  const after = res.headers.getSetCookie().join('; ')
  assert.ok(!after.includes(first.pair), `spent entry still present: ${after}`)
  assert.ok(after.includes(second.pair), `other tab was evicted: ${after}`)
})

test('an unapproved sign-in reports pending and keeps the session', async () => {
  approved = false
  const session = await startSession(await register())
  const res = await complete(session.sid, cookieHeader(session.pairs))
  assert.equal(res.status, 200)
  const page = await res.text()
  assert.match(page, /Not connected yet/)
  assert.ok(!res.headers.getSetCookie().some((c) => !c.includes(session.pair)), 'a pending reload keeps the binding')
})

test('complete is rate-limited, and junk probes do not spend the budget', async () => {
  const limited = await startServer({ ANON_AUTH_COMPLETE_PER_HOUR: '1' })
  const clientId = await register(limited)
  approved = true

  // Unauthenticated guesses: no session at all, or a real session whose
  // request does not carry its cookie.
  assert.equal((await complete('a'.repeat(32), undefined, limited)).status, 400)
  const noCookie = await startSession(clientId, '', limited)
  assert.equal((await complete(noCookie.sid, undefined, limited)).status, 400)

  // The first real completion is still allowed.
  const first = await startSession(clientId, '', limited)
  assert.equal((await complete(first.sid, cookieHeader(first.pairs), limited)).status, 302)

  // The second one over the budget is refused with a reset hint.
  const next = await startSession(clientId, '', limited)
  const capped = await complete(next.sid, cookieHeader(next.pairs), limited)
  assert.equal(capped.status, 429)
  const retry = Number(capped.headers.get('retry-after'))
  assert.ok(retry > 0 && retry <= 3600, `Retry-After ${retry}`)
  assert.match(await capped.text(), /Too many sign-in attempts/)
})
