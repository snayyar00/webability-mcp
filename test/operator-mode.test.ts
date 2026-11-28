/**
 * #227: a caller holding MCP_AUTH_TOKEN was neither anonymous (the anonymous
 * limiter skipped it) nor identified (authToken is not set, so account tools
 * ran on the deploy's own WEBABILITY_API_KEY) — unbounded spend, site creation
 * and payment links on our account, with no telemetry attribution.
 *
 * The token still works (backward compat for server-to-server callers), but
 * every tool call it makes is now budgeted per IP per class on its own
 * counters, the 429 names the operator env var instead of telling a credential
 * holder to sign up, and telemetry attributes the traffic to a constant
 * operator distinct id.
 *
 * Offline: real src/http.ts against a mock platform API, plus in-process unit
 * assertions on the pure helpers.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:http'
import { createServer as createPort } from 'node:net'
import { after, before, test } from 'node:test'
import { setTimeout as sleep } from 'node:timers/promises'

import { operatorLimitClass, operatorLimitMessage } from '../src/anonGate.ts'
import { analyticsIdentity } from '../src/posthog.ts'

const OPERATOR_TOKEN = 'operator-shared-token-0123456789abcdefghijkl'
const DEPLOY_KEY = 'deploy-own-api-key'

let api: ReturnType<typeof createServer>
let apiUrl = ''
/** Authorization headers the platform mock saw, in order. */
const seenAuth: string[] = []
const children: ChildProcess[] = []

before(async () => {
  api = createServer((req, res) => {
    let raw = ''
    req.on('data', (c: Buffer) => (raw += c.toString()))
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/graphql') {
        seenAuth.push(String(req.headers.authorization || ''))
        res.end(JSON.stringify({ data: { getUserSites: { sites: [], total: 0 } } }))
        return
      }
      // Anything else is a token check: accept, so only the operator path is
      // under test here.
      res.end('{}')
    })
  })
  const listening = Promise.withResolvers<void>()
  api.listen(0, '127.0.0.1', listening.resolve)
  await listening.promise
  apiUrl = `http://127.0.0.1:${socketPort(api)}`
})

after(() => {
  for (const child of children) child.kill()
  api?.close()
})

/** The port a listening server bound to. */
function socketPort(server: ReturnType<typeof createPort> | typeof api): number {
  const address = server.address()
  assert.ok(address && typeof address === 'object', 'server is not listening on a socket')
  return address.port
}

async function freePort(): Promise<number> {
  const probe = createPort()
  const listening = Promise.withResolvers<void>()
  probe.listen(0, listening.resolve)
  await listening.promise
  const port = socketPort(probe)
  const closed = Promise.withResolvers<void>()
  probe.close(closed.resolve)
  await closed.promise
  return port
}

/**
 * A real hosted server against the mock platform, started with the operator
 * token. The readiness loop needs real time: it waits on another process
 * binding a socket, so a fake clock has nothing to advance.
 */
async function startOperatorServer(env: Record<string, string>): Promise<string> {
  const port = await freePort()
  const base = `http://127.0.0.1:${port}`
  const child = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: {
      ...process.env,
      PORT: String(port),
      WEBABILITY_API_URL: apiUrl,
      MCP_PUBLIC_URL: base,
      MCP_AUTH_TOKEN: OPERATOR_TOKEN,
      WEBABILITY_API_KEY: DEPLOY_KEY,
      OAUTH_SIGNING_SECRET: 'operator-mode-test-secret-0123456789abcdef',
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

interface Call {
  id: number
  name: string
  args: Record<string, unknown>
}

const call = (c: Call) => ({ jsonrpc: '2.0', id: c.id, method: 'tools/call', params: { name: c.name, arguments: c.args } })

/** `detect_framework` is heavy; a loopback url is refused by the SSRF guard
 * after the gate has counted it, so no browser launches. */
const heavy = (id: number): Call => ({ id, name: 'detect_framework', args: { url: 'http://127.0.0.1:9/' } })
const listSites = (id: number): Call => ({ id, name: 'list_sites', args: {} })

async function post(base: string, body: unknown, token?: string): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
}

/** The JSON-RPC error of a 429, asserted present. */
async function errorOf(res: Response): Promise<{ message: string; data: Record<string, unknown> }> {
  const payload: unknown = await res.json()
  assert.ok(payload && typeof payload === 'object' && 'error' in payload, `no error in ${JSON.stringify(payload)}`)
  const error = payload.error
  assert.ok(error && typeof error === 'object' && 'message' in error && typeof error.message === 'string' && 'data' in error)
  assert.ok(error.data && typeof error.data === 'object')
  return { message: error.message, data: Object.fromEntries(Object.entries(error.data)) }
}

test('operator classes cover the account tools, which the anonymous gate ignores', () => {
  assert.equal(operatorLimitClass({ name: 'list_sites' }), 'account')
  assert.equal(operatorLimitClass({ name: 'create_upgrade_link' }), 'account')
  assert.equal(operatorLimitClass({ name: 'get_audit' }), 'account')
  assert.equal(operatorLimitClass({ name: 'scan_page' }), 'heavy')
  assert.equal(operatorLimitClass({ name: 'generate_ai_fix' }), 'ai')
  // Pure text, no browser and no API call.
  assert.equal(operatorLimitClass({ name: 'get_install_snippet' }), null)
})

test('the operator message names the env var and does not tell a key holder to sign up', () => {
  const msg = operatorLimitMessage({ cls: 'account', limit: 1, retryAfterS: 3600, resetAt: Date.UTC(2026, 10, 27, 15, 5, 0) })
  assert.match(msg, /Operator token limit reached: 1 account call per hour/)
  assert.match(msg, /OPERATOR_ACCOUNT_PER_HOUR/)
  assert.match(msg, /resets in 60 min \(at 15:05 UTC\)/)
  assert.match(msg, /Use a WebAbility user token/)
  assert.doesNotMatch(msg, /free WebAbility account/, 'the credential holder is not the audience for the sign-up pitch')
  const heavyMsg = operatorLimitMessage({ cls: 'heavy', limit: 2, retryAfterS: 30, resetAt: Date.UTC(2026, 10, 27, 15, 5, 0) })
  assert.match(heavyMsg, /OPERATOR_HEAVY_PER_HOUR/)
  assert.match(heavyMsg, /2 page-loading calls/)
})

test('telemetry attributes the operator to a constant id, never to the shared secret', () => {
  assert.deepEqual(analyticsIdentity({ operator: true, authToken: undefined }), {
    distinctId: 'webability-operator',
    properties: { auth_source: 'operator_token' },
  })
  const identified = analyticsIdentity({ authToken: 'user-token' })
  assert.ok(identified)
  assert.match(identified.distinctId, /^webability-token:/)
  assert.ok(!identified.distinctId.includes('user-token'), 'raw token must not be the distinct id')
  assert.equal(analyticsIdentity({}), null, 'anonymous traffic stays anonymous')
})

test('operator heavy calls are capped per IP, and the 429 names the limit', async () => {
  const base = await startOperatorServer({ OPERATOR_HEAVY_PER_HOUR: '2' })
  assert.equal((await post(base, call(heavy(1)), OPERATOR_TOKEN)).status, 200)
  assert.equal((await post(base, call(heavy(2)), OPERATOR_TOKEN)).status, 200)

  const capped = await post(base, call(heavy(3)), OPERATOR_TOKEN)
  assert.equal(capped.status, 429)
  const retry = Number(capped.headers.get('retry-after'))
  assert.ok(retry > 0 && retry <= 3600, `Retry-After ${retry}`)
  const { message, data } = await errorOf(capped)
  assert.match(message, /Operator token limit reached: 2 page-loading calls/)
  assert.match(message, /OPERATOR_HEAVY_PER_HOUR/)
  assert.equal(data.limit, 2)
  assert.equal(typeof data.resetAt, 'string')

  // Separate buckets: exhausting the operator budget must not throttle a
  // caller who has no token at all.
  assert.equal((await post(base, call(heavy(4)))).status, 200, 'anonymous traffic keeps its own budget')
})

test('a batch cannot hide extra calls past the operator budget', async () => {
  const base = await startOperatorServer({ OPERATOR_HEAVY_PER_HOUR: '2' })
  // Three heavy calls in one JSON-RPC batch: the gate counts tool calls, not
  // requests, so the third one trips the budget for the whole request.
  const capped = await post(base, [call(heavy(1)), call(heavy(2)), call(heavy(3))], OPERATOR_TOKEN)
  assert.equal(capped.status, 429)
  assert.match((await errorOf(capped)).message, /Operator token limit reached: 2 page-loading calls/)
})

test('operator account tools are capped and run on the deploy key', async () => {
  const base = await startOperatorServer({ OPERATOR_ACCOUNT_PER_HOUR: '1' })
  const first = await post(base, call(listSites(1)), OPERATOR_TOKEN)
  assert.equal(first.status, 200)
  assert.match(await first.text(), /No sites on this account yet/)
  assert.deepEqual(seenAuth.slice(-1), [`Bearer ${DEPLOY_KEY}`], 'the account tool ran on the deploy key, which is the risk being capped')

  const capped = await post(base, call(listSites(2)), OPERATOR_TOKEN)
  assert.equal(capped.status, 429)
  const { message, data } = await errorOf(capped)
  assert.match(message, /Operator token limit reached: 1 account call/)
  assert.match(message, /OPERATOR_ACCOUNT_PER_HOUR/)
  assert.equal(data.limit, 1)
})

test('a user token is not the operator: the shared budget does not touch it', async () => {
  const base = await startOperatorServer({ OPERATOR_HEAVY_PER_HOUR: '1' })
  assert.equal((await post(base, call(heavy(1)), OPERATOR_TOKEN)).status, 200)
  assert.equal((await post(base, call(heavy(2)), OPERATOR_TOKEN)).status, 429)
  // A per-user token resolves to that user's account and is not budgeted here.
  const user = await post(base, call(listSites(3)), 'some-user-token')
  assert.equal(user.status, 200)
})
