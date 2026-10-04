/**
 * An anonymous call to an account tool must not disconnect the client.
 *
 * Before: the hosted /mcp answered an anonymous visual_audit / start_audit /
 * get_audit with HTTP 401 + WWW-Authenticate. Claude Code then caches the
 * server as `needs-auth`, and every later session on that machine lists zero
 * tools (real-client transcripts in the PR). Now /mcp answers with a normal
 * tool result (isError) that says how to sign in, and /mcp/auth is the URL that
 * always challenges, for clients that start OAuth only on a 401.
 *
 * Spawns the real HTTP entry against a mock platform API. No network.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer as createHttp, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { after, before, test } from 'node:test'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const here = dirname(fileURLToPath(import.meta.url))
const USER_TOKEN = 'wa_live_anon_account_tools_token'
const ACCOUNT_TOOLS = ['visual_audit', 'start_audit', 'get_audit'] as const
const ARGS: Record<string, unknown> = { url: 'https://webability.io', id: 1 }

let api: Server
let child: ChildProcess
let BASE = ''

before(async () => {
  api = createHttp((req, res) => {
    res.setHeader('Content-Type', 'application/json')
    if (req.url === '/cli/whoami') {
      const transient: Record<string, [number, string | null]> = {
        'Bearer throttled-token': [429, '120'],
        'Bearer timeout-token': [408, null],
        'Bearer too-early-token': [425, null],
      }
      const t = transient[String(req.headers.authorization)]
      if (t) {
        res.statusCode = t[0] // throttled / transient: not a verdict on the token
        if (t[1]) res.setHeader('Retry-After', t[1])
        res.end('{}')
        return
      }
      if (req.headers.authorization === 'Bearer api-outage-token') {
        res.statusCode = 502 // the account API is down, not a verdict on the token
        res.end('{}')
        return
      }
      res.statusCode = req.headers.authorization === `Bearer ${USER_TOKEN}` ? 200 : 401
      res.end('{}')
      return
    }
    if (req.url?.startsWith('/cli/audit/')) {
      // A signed-in get_audit reaches the API: 404 = "no audit with that id".
      res.statusCode = req.headers.authorization === `Bearer ${USER_TOKEN}` ? 404 : 401
      res.end('{}')
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r))
  const port = 21000 + Math.floor(Math.random() * 2000)
  BASE = `http://127.0.0.1:${port}`
  child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
    env: {
      ...process.env,
      PORT: String(port),
      WEBABILITY_API_URL: `http://127.0.0.1:${(api.address() as AddressInfo).port}`,
      MCP_PUBLIC_URL: BASE,
      OAUTH_SIGNING_SECRET: 'anon-account-tools-secret-0123456789',
      WEBABILITY_API_KEY: 'operator-key-must-never-serve-anon',
      ANON_AI_PER_HOUR: '2',
      TRUSTED_PROXY_HOPS: '1',
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  })
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${BASE}/health`)).ok) return
    } catch {}
    await new Promise((r) => setTimeout(r, 200))
  }
  throw new Error('server did not start')
})

after(() => {
  child?.kill()
  api?.close()
})

let nextId = 1
const call = (name: string, args: unknown = ARGS) => ({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name, arguments: args } })
async function post(body: unknown, headers: Record<string, string> = {}, path = '/mcp') {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  let json: any
  try {
    json = JSON.parse(text)
  } catch {}
  return { status: res.status, www: res.headers.get('www-authenticate'), json, text }
}
const resultText = (r: any) => (r?.result?.content ?? []).map((c: any) => c.text).join('\n')

for (const tool of ACCOUNT_TOOLS) {
  test(`anonymous ${tool} on /mcp → 200 tool result with isError, no 401 and no WWW-Authenticate`, async () => {
    const r = await post(call(tool))
    assert.equal(r.status, 200, r.text.slice(0, 200))
    assert.equal(r.www, null)
    assert.equal(r.json?.result?.isError, true)
    const text = resultText(r.json)
    assert.match(text, new RegExp(`${tool} needs a free WebAbility account`))
    assert.match(text, /claude mcp login/)
    assert.match(text, /codex mcp login/)
    assert.ok(text.includes(`${BASE}/mcp/auth`), text)
    assert.match(text, /scan and check tools keep working/)
  })
}

test('a free tool still runs after an anonymous account-tool call', async () => {
  await post(call('visual_audit'))
  const r = await post(call('get_rules', { tags: ['wcag2aa'] }))
  assert.equal(r.status, 200)
  assert.notEqual(r.json?.result?.isError, true)
  assert.match(resultText(r.json), /\S/)
})

test('batch with one account tool and one free tool → both answered, only the account tool refused', async () => {
  const paid = call('visual_audit')
  const free = call('get_rules', { tags: ['wcag2aa'] })
  const r = await post([paid, free])
  assert.equal(r.status, 200, r.text.slice(0, 200))
  assert.equal(r.www, null)
  assert.ok(Array.isArray(r.json), r.text.slice(0, 200))
  const byId = new Map(r.json.map((m: any) => [m.id, m]))
  assert.equal((byId.get(paid.id) as any)?.result?.isError, true)
  assert.match(resultText(byId.get(paid.id)), /needs a free WebAbility account/)
  assert.notEqual((byId.get(free.id) as any)?.result?.isError, true)
})

test('anonymous tools/list on /mcp is unchanged: account tools still listed', async () => {
  const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} })
  assert.equal(r.status, 200)
  const names = r.json.result.tools.map((t: any) => t.name)
  for (const t of [...ACCOUNT_TOOLS, 'scan_page', 'get_rules']) assert.ok(names.includes(t), t)
})

test('signed-in token on /mcp runs an account tool on the caller account', async () => {
  const r = await post(call('get_audit', { id: 1 }), { authorization: `Bearer ${USER_TOKEN}` })
  assert.equal(r.status, 200)
  const text = resultText(r.json)
  assert.doesNotMatch(text, /needs a free WebAbility account/)
  assert.match(text, /No audit #1 for this account/)
})

test('invalid token → 401 + WWW-Authenticate on /mcp, for a free tool and for an account tool', async () => {
  for (const name of ['get_rules', 'visual_audit']) {
    const r = await post(call(name), { authorization: 'Bearer not-a-real-token' })
    assert.equal(r.status, 401, name)
    assert.ok(r.www?.includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`), `${name}: ${r.www}`)
  }
})

test('anonymous rate limit still applies on /mcp (AI cap = 2)', async () => {
  const fix = () => call('generate_ai_fix', { issue: { message: 'x' }, html: '<p>x</p>', framework: 'plain-css' })
  let last
  for (let i = 0; i < 3; i++) last = await post(fix(), { 'x-forwarded-for': `203.0.113.${i}, 198.51.100.7` })
  assert.equal(last!.status, 429)
  // The sign-in URL in the 429 is built from MCP_PUBLIC_URL, not hard-coded.
  assert.ok(last!.json?.error?.message?.includes(`${BASE}/mcp/auth`), last!.text.slice(0, 400))
  assert.doesNotMatch(last!.json?.error?.message ?? '', /authenticate option/i)
})

test('X-Forwarded-For: the caller-written leftmost entry does not mint a fresh anonymous bucket', async () => {
  // TRUSTED_PROXY_HOPS=1 → the bucket is the rightmost entry. Three requests with
  // three different leftmost values share 198.51.100.9's bucket, so the third trips.
  const fix = () => call('generate_ai_fix', { issue: { message: 'x' }, html: '<p>x</p>', framework: 'plain-css' })
  const statuses = []
  for (let i = 0; i < 3; i++) statuses.push((await post(fix(), { 'x-forwarded-for': `10.0.0.${i}, 198.51.100.9` })).status)
  assert.equal(statuses[2], 429, statuses.join(','))
})

test('/mcp/auth: anonymous initialize → 401 + WWW-Authenticate naming the /mcp/auth metadata', async () => {
  const r = await post(
    { jsonrpc: '2.0', id: nextId++, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } },
    {},
    '/mcp/auth',
  )
  assert.equal(r.status, 401)
  assert.ok(r.www?.includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp/auth"`), String(r.www))
})

test('/mcp/auth: protected-resource metadata names /mcp/auth as the resource', async () => {
  const res = await fetch(`${BASE}/.well-known/oauth-protected-resource/mcp/auth`)
  assert.equal(res.status, 200)
  const j = await res.json()
  assert.equal(j.resource, `${BASE}/mcp/auth`)
  assert.deepEqual(j.authorization_servers, [BASE])
})

test('/mcp/auth: signed-in token lists and runs every tool', async () => {
  const headers = { authorization: `Bearer ${USER_TOKEN}` }
  const list = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} }, headers, '/mcp/auth')
  assert.equal(list.status, 200)
  assert.ok(list.json.result.tools.some((t: any) => t.name === 'visual_audit'))
  const r = await post(call('get_audit', { id: 1 }), headers, '/mcp/auth')
  assert.match(resultText(r.json), /No audit #1 for this account/)
})

test('/mcp/auth: invalid token → 401', async () => {
  const r = await post(call('get_rules', { tags: ['wcag2aa'] }), { authorization: 'Bearer nope' }, '/mcp/auth')
  assert.equal(r.status, 401)
})

test('anonymous visual_audit refuses before it opens a browser', async () => {
  // 203.0.113.10 (TEST-NET-3) passes the hosted URL guard with no DNS lookup and
  // never answers: if the refusal came after the capture, this call would sit
  // in the browser until the capture deadline instead of returning at once.
  const [ct, st] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, anonymous: true })
  const client = new Client({ name: 't', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(st), client.connect(ct)])
  const started = Date.now()
  const r: any = await client.callTool({ name: 'visual_audit', arguments: { url: 'https://203.0.113.10/' } })
  assert.equal(r.isError, true)
  assert.match(r.content[0].text, /visual_audit needs a free WebAbility account/)
  assert.match(r.content[0].text, /scan and check tools keep working/)
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started}ms`)
  await client.close()
})

test('anonymous account tool with a blocked URL gets the sign-in steps, not the URL guard (no DNS work)', async () => {
  for (const url of ['http://localhost:3000', 'http://169.254.169.254/']) {
    const r = await post(call('visual_audit', { url }))
    assert.equal(r.status, 200)
    assert.match(resultText(r.json), /visual_audit needs a free WebAbility account/, url)
  }
})

test('/mcp/auth: invalid token → WWW-Authenticate names the /mcp/auth metadata', async () => {
  const r = await post(call('get_rules', { tags: ['wcag2aa'] }), { authorization: 'Bearer nope' }, '/mcp/auth')
  assert.equal(r.status, 401)
  assert.ok(r.www?.includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp/auth"`), String(r.www))
})

test('/mcp/auth: a valid token in x-webability-token (gateway header) is accepted', async () => {
  const r = await post(call('get_audit', { id: 1 }), { 'x-webability-token': USER_TOKEN }, '/mcp/auth')
  assert.equal(r.status, 200)
  assert.match(resultText(r.json), /No audit #1 for this account/)
})

test('/mcp/ and /mcp/auth/ (trailing slash) are not MCP endpoints', async () => {
  for (const p of ['/mcp/', '/mcp/auth/']) assert.equal((await post(call('get_rules', { tags: ['wcag2aa'] }), {}, p)).status, 404, p)
})

test('/.well-known/oauth-authorization-server/mcp/auth serves the AS metadata', async () => {
  const res = await fetch(`${BASE}/.well-known/oauth-authorization-server/mcp/auth`)
  assert.equal(res.status, 200)
  assert.equal((await res.json()).issuer, BASE)
})

test('sign-in text has no trial / paid / credit wording and no internal names', async () => {
  const r = await post(call('start_audit'))
  assert.doesNotMatch(resultText(r.json), /trial|paid|credit|abilyo/i)
})

test('account API outage while checking a token → 503 + Retry-After, never 401 (would disconnect signed-in clients)', async () => {
  for (const path of ['/mcp', '/mcp/auth']) {
    const r = await post(call('get_rules', { tags: ['wcag2aa'] }), { authorization: 'Bearer api-outage-token' }, path)
    assert.equal(r.status, 503, path)
    assert.equal(r.www, null, path)
  }
})

test('throttled or transient whoami (429 / 408 / 425) → 503, never 401; upstream Retry-After is passed on', async () => {
  for (const [tok, retry] of [['throttled-token', '120'], ['timeout-token', null], ['too-early-token', null]] as const) {
    const r = await post(call('get_rules', { tags: ['wcag2aa'] }), { authorization: `Bearer ${tok}` }, '/mcp/auth')
    assert.equal(r.status, 503, tok)
    assert.equal(r.www, null, tok)
    const res = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tok}` },
      body: JSON.stringify(call('get_rules', { tags: ['wcag2aa'] })),
    })
    assert.equal(res.status, 503, tok)
    assert.equal(res.headers.get('retry-after'), retry ?? '30', tok)
  }
})

test('sign-in steps do not hard-code a server name', async () => {
  const text = resultText((await post(call('visual_audit'))).json)
  assert.match(text, /claude mcp login <server-name>/)
  assert.match(text, /codex mcp login <server-name>/)
  assert.doesNotMatch(text, /mcp login webability/)
})
