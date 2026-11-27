import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer as httpServer } from 'node:http'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createServer } from '../src/server.ts'

const target = 'https://8.8.8.8/pricing?q=1'
const scriptUrl = 'https://widget.webability.io/widget.min.js'
const observations = {
  installed: { kind: 'script', scriptUrl, httpStatus: 200 },
  blocked: { kind: 'consent', scriptUrl, type: 'text/plain', attributes: { 'data-cookieconsent': 'preferences' } },
  error: { kind: 'script_load', scriptUrl, httpStatus: 404 },
  not_installed: { kind: 'absence', inspectedScriptUrls: [], observationDurationMs: 5100 },
}
function diagnosis(state: keyof typeof observations) {
  return { url: target, finalUrl: target, state, sentence: 'Observation.', nextStep: 'Next action.', evidence: [observations[state]] }
}
const failure = { error: 'check_failed', sentence: 'Could not open the page.', nextStep: 'Try again.' }

test('hosted check_install forwards the caller and preserves MCP states, evidence and failures', async t => {
  process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
  for (const anonymous of [true, false]) {
    const server = createServer({ remote: true, anonymous, authToken: 'caller' })
    const client = new Client({ name: 'test', version: '1' })
    const [c, s] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(s), client.connect(c)])
    t.after(() => client.close())
    assert.ok((await client.listTools()).tools.some(tool => tool.name === 'check_install'))
    const call = (url: string) => client.callTool({ name: 'check_install', arguments: { url } })
    let response = Response.json(diagnosis('installed'))
    const fetch = t.mock.method(globalThis, 'fetch', (endpoint, init) => {
      assert.equal(new URL(endpoint).pathname, '/check-install')
      assert.equal(init.method, 'POST')
      assert.deepEqual(JSON.parse(init.body), { url: target })
      assert.equal(init.headers.Authorization, anonymous ? undefined : 'Bearer caller')
      return response
    })
    const privateCall = await call('http://127.0.0.1/')
    assert.equal(privateCall.isError, true)
    assert.equal(fetch.mock.callCount(), 0)
    for (const state of ['installed', 'error'] as const) {
      response = Response.json(diagnosis(state))
      const result = await call(target + '#fragment')
      assert.ok(!result.isError)
      assert.deepEqual(result.structuredContent, { ...diagnosis(state), state: state === 'installed' ? 'present' : state })
    }
    response = Response.json(failure, { status: 502 })
    const unknown = await call(target)
    assert.equal(unknown.isError, true)
    assert.ok(!('state' in (unknown.structuredContent ?? {})))
    assert.match(JSON.stringify(unknown.content), /HTTP 502.*Could not open the page.*Try again/)
    fetch.mock.restore()
  }
})

test('CLI writes complete diagnoses to stdout and failures to stderr with distinct process exits', async t => {
  let status = 200
  let body: unknown
  let requests = 0
  const api = httpServer((req, res) => {
    requests++
    assert.equal(req.url, '/check-install')
    assert.equal(req.headers.authorization, 'Bearer cli-test')
    res.writeHead(status).end(JSON.stringify(body))
  })
  api.listen(0, '127.0.0.1')
  await once(api, 'listening')
  t.after(() => api.close())
  const base = 'http://127.0.0.1:' + (api.address() as AddressInfo).port
  async function cli(args: string[], endpoint = base) {
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      env: { ...process.env, WEBABILITY_API_URL: endpoint, WEBABILITY_API_KEY: 'cli-test' },
    })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    const [code] = await once(child, 'close')
    return { code, stdout, stderr }
  }
  for (const state of Object.keys(observations) as Array<keyof typeof observations>) {
    body = diagnosis(state)
    const result = await cli(['check-install', target])
    assert.equal(result.code, state === 'installed' ? 0 : 1)
    assert.equal(result.stderr, '')
    assert.deepEqual(JSON.parse(result.stdout), body)
  }
  for (const [httpStatus, payload, message] of [
    [400, failure, /HTTP 400/], [429, failure, /at least one minute/], [502, failure, /HTTP 502.*Retry/],
    [200, { ...diagnosis('installed'), evidence: [] }, /Invalid check-install response/],
    [200, { ...diagnosis('installed'), state: 'unknown' }, /Invalid check-install response/],
  ] as const) {
    status = httpStatus
    body = payload
    const result = await cli(['check-install', target])
    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, message)
  }
  const before = requests
  for (const args of [[], ['check-install', 'localhost:8080'], ['check-install', 'https://user:pass@example.com/']]) {
    const result = await cli(args)
    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
  }
  assert.equal(requests, before)
  const offline = await cli(['check-install', target], 'http://127.0.0.1:1')
  assert.equal(offline.code, 2)
  assert.equal(offline.stdout, '')
  assert.match(offline.stderr, /fetch failed/)
})

test('local MCP observes a localhost page without calling the API', async t => {
  const page = httpServer((_req, res) => res.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>Local lab</title>'))
  page.listen(0, '127.0.0.1')
  await once(page, 'listening')
  t.after(() => page.close())
  const url = 'http://127.0.0.1:' + (page.address() as AddressInfo).port + '/'
  const server = createServer()
  const client = new Client({ name: 'test', version: '1' })
  const [c, s] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(s), client.connect(c)])
  t.after(() => client.close())
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected API request') })
  const result = await client.callTool({ name: 'check_install', arguments: { url } })
  assert.equal(result.structuredContent?.state, 'not_installed')
  assert.equal(result.structuredContent?.finalUrl, url)
  assert.equal(fetch.mock.callCount(), 0)
})
