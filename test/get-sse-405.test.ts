/**
 * The hosted server is stateless, so it has nothing to push on a standing GET
 * stream. A GET that hangs is worse than none: no response headers reach
 * Cloudflare, it answers 524 at 125s, and Cursor marks the server failed two
 * minutes after a good sign-in. The spec's other answer is 405, which every
 * client treats as "no GET stream here".
 *
 * Offline: real src/http.ts against a mock platform API.
 */
import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

const here = dirname(fileURLToPath(import.meta.url))
const GOOD = 'good-token'

let api: Server
let child: ChildProcess
let BASE = ''

before(async () => {
  api = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      const token = (req.headers.authorization || '').replace('Bearer ', '')
      res.setHeader('Content-Type', 'application/json')
      res.statusCode = req.url === '/cli/whoami' && token === GOOD ? 200 : 401
      res.end('{}')
    })
  })
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r))
  const apiPort = (api.address() as { port: number }).port
  const port = 26000 + Math.floor(Math.random() * 2000)
  BASE = `http://127.0.0.1:${port}`
  child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
    env: { ...process.env, PORT: String(port), WEBABILITY_API_URL: `http://127.0.0.1:${apiPort}`, MCP_PUBLIC_URL: BASE, OAUTH_SIGNING_SECRET: 'get-sse-test-secret-0123456789abcdef' },
    stdio: ['ignore', 'ignore', 'inherit'],
  })
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(`${BASE}/health`)
      return
    } catch {
      await new Promise((r) => setTimeout(r, 100))
    }
  }
  throw new Error('server did not start')
})

after(() => {
  child?.kill()
  api?.close()
})

const getStream = (path: string, headers: Record<string, string> = {}) =>
  fetch(`${BASE}${path}`, { headers: { accept: 'text/event-stream', ...headers }, signal: AbortSignal.timeout(3000) })

test('GET /mcp answers 405 at once and names the allowed methods', async () => {
  const res = await getStream('/mcp')
  assert.equal(res.status, 405)
  const allow = res.headers.get('allow') ?? ''
  assert.match(allow, /POST/)
  assert.doesNotMatch(allow, /GET/)
})

test('GET /mcp/auth with a valid token answers 405, the path Cursor takes after sign-in', async () => {
  const res = await getStream('/mcp/auth', { authorization: `Bearer ${GOOD}` })
  assert.equal(res.status, 405)
})

test('GET /mcp/auth with no token still answers 401 so the client signs in', async () => {
  const res = await getStream('/mcp/auth')
  assert.equal(res.status, 401)
  assert.match(res.headers.get('www-authenticate') ?? '', /resource_metadata/)
})

test('a real SDK client gets 405 on its GET stream, stays connected, and reports no error', async () => {
  const errors: Error[] = []
  const getStatuses: number[] = []
  const recordingFetch: typeof fetch = async (input, init) => {
    const res = await fetch(input, init)
    if ((init?.method ?? 'GET') === 'GET') getStatuses.push(res.status)
    return res
  }
  const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { fetch: recordingFetch })
  const client = new Client({ name: 'get-sse-test', version: '0' })
  client.onerror = (e) => errors.push(e)
  await client.connect(transport)
  const { tools } = await client.listTools()
  assert.ok(tools.length > 0)
  await new Promise((r) => setTimeout(r, 500))
  await client.close()
  assert.deepEqual(getStatuses, [405])
  assert.deepEqual(errors.map((e) => e.message), [])
})
