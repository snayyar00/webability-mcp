/**
 * The hosted MCP proves itself to the platform judge with `x-mcp-internal`.
 *
 * POST /api/judge-incomplete spends model money, so the platform only answers
 * the hosted MCP (shared secret MCP_TRIAL_INTERNAL_SECRET, already set on the
 * hosted deploy) or a signed-in user's bearer. Anonymous hosted scans have no
 * bearer, so without the header every one of them was judged by nobody.
 *
 * Local (stdio/npm) installs never send the header: they never hold the
 * secret, and they talk to their own model endpoint, not the platform.
 *
 * A local stub stands in for the platform and the model; the real scan_html
 * tool runs end to end.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type IncomingHttpHeaders, type Server as HttpServer } from 'node:http'
import { after, before, beforeEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { judgeOptionsFromEnv } from '../src/judgeConfig.ts'

// axe reports video-caption as incomplete in jsdom (it cannot hear the track) → one undecided item.
// A fresh src per scan keeps core's verdict cache from answering instead of the endpoint.
let n = 0
const snippet = () => `<video src="/v${++n}.mp4" controls width="320" height="180"></video>`
const SECRET = 'hosted-internal-secret-for-test'

let stub: HttpServer
const calls: Array<{ path: string; headers: IncomingHttpHeaders }> = []
let createServer: typeof import('../src/server.ts').createServer

before(async () => {
  stub = createHttpServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      calls.push({ path: req.url || '', headers: req.headers })
      const parsed = JSON.parse(body)
      if (req.url === '/api/judge-incomplete') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ verdicts: parsed.items.map((i: { id: string }) => ({ id: i.id, verdict: 'violation', reason: 'spoken content with no captions' })) }))
        return
      }
      const text = JSON.stringify(parsed.messages)
      const ids = [...new Set([...text.matchAll(/\\"id\\": \\"([^"\\]+)\\"/g)].map((m) => m[1]))]
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(ids.map((id) => ({ id, verdict: 'violation', reason: 'no captions' }))) } }] }))
    })
  })
  await new Promise<void>((r) => stub.listen(0, '127.0.0.1', () => r()))
  const origin = `http://127.0.0.1:${(stub.address() as any).port}`
  // server.ts reads the platform origin once at load.
  process.env.WEBABILITY_API_URL = origin
  process.env.WEBABILITY_JUDGE_BASE_URL = `${origin}/v1`
  ;({ createServer } = await import('../src/server.ts'))
})
after(() => stub?.close())
beforeEach(() => {
  calls.length = 0
  delete process.env.MCP_TRIAL_INTERNAL_SECRET
  delete process.env.OPENROUTER_API_KEY
})

async function scanHtml(opts: Parameters<typeof createServer>[0]) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer(opts)
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'scan_html', arguments: { html: snippet() } }, undefined, { timeout: 120_000 })
  await client.close()
  return (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
}

const judgeCalls = () => calls.filter((c) => c.path === '/api/judge-incomplete')

test('hosted, signed in: the judge call carries x-mcp-internal AND the user bearer', async () => {
  process.env.MCP_TRIAL_INTERNAL_SECRET = SECRET
  const text = await scanHtml({ remote: true, authToken: 'user-token-abc' })
  assert.equal(judgeCalls().length, 1, text.slice(0, 400))
  assert.equal(judgeCalls()[0].headers['x-mcp-internal'], SECRET)
  assert.equal(judgeCalls()[0].headers.authorization, 'Bearer user-token-abc')
  assert.match(text, /video-caption/)
})

test('hosted, anonymous: x-mcp-internal is sent, no bearer', async () => {
  process.env.MCP_TRIAL_INTERNAL_SECRET = SECRET
  await scanHtml({ remote: true, anonymous: true })
  assert.equal(judgeCalls().length, 1)
  assert.equal(judgeCalls()[0].headers['x-mcp-internal'], SECRET)
  assert.equal(judgeCalls()[0].headers.authorization, undefined)
})

test('hosted, secret not configured: no x-mcp-internal header (bearer still sent)', async () => {
  await scanHtml({ remote: true, authToken: 'user-token-abc' })
  assert.equal(judgeCalls().length, 1)
  assert.equal(judgeCalls()[0].headers['x-mcp-internal'], undefined)
  assert.equal(judgeCalls()[0].headers.authorization, 'Bearer user-token-abc')
})

test('local install: never sends x-mcp-internal, even if the env var happens to be set', async () => {
  process.env.MCP_TRIAL_INTERNAL_SECRET = SECRET
  process.env.OPENROUTER_API_KEY = 'local-operator-key'
  await scanHtml({})
  assert.equal(judgeCalls().length, 0, 'local never calls the platform judge')
  assert.equal(calls.length, 1, 'local calls its own model endpoint')
  assert.equal(calls[0].path, '/v1/chat/completions')
  assert.equal(calls[0].headers['x-mcp-internal'], undefined)
  assert.equal(calls[0].headers.authorization, 'Bearer local-operator-key')
})

test('judgeOptionsFromEnv: internalSecret only in remote mode', () => {
  const env = { MCP_TRIAL_INTERNAL_SECRET: SECRET, OPENROUTER_API_KEY: 'k' } as NodeJS.ProcessEnv
  assert.equal(judgeOptionsFromEnv({ remote: true, apiUrl: 'https://api.webability.io' }, env)?.internalSecret, SECRET)
  assert.equal(judgeOptionsFromEnv({ remote: false, apiUrl: 'https://api.webability.io' }, env)?.internalSecret, undefined)
  assert.equal(judgeOptionsFromEnv({ remote: true, apiUrl: 'https://api.webability.io' }, { MCP_TRIAL_INTERNAL_SECRET: '  ' } as NodeJS.ProcessEnv)?.internalSecret, undefined, 'blank secret = not configured')
  assert.equal(judgeOptionsFromEnv({ remote: true, apiUrl: 'https://api.webability.io' }, { WEBABILITY_JUDGE: 'off', MCP_TRIAL_INTERNAL_SECRET: SECRET } as NodeJS.ProcessEnv), undefined)
})
