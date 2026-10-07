/**
 * Smithery / SEP-1649 static server card: GET /.well-known/mcp/server-card.json
 * must describe the hosted server from the same sources the live server uses
 * (version.ts, the real tools/list, server.json) — never a hand-written copy.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer as netServer } from 'node:net'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import { MCP_VERSION } from '../src/version.ts'

const PATH = '/.well-known/mcp/server-card.json'

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = netServer().listen(0, () => {
      const p = (s.address() as { port: number }).port
      s.close(() => resolve(p))
    })
  })
}

let proc: ChildProcess
let base: string
before(async () => {
  const port = await freePort()
  proc = spawn('./node_modules/.bin/tsx', ['src/http.ts'], { env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'] })
  base = `http://127.0.0.1:${port}`
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(base + '/health')).ok) return } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  proc.kill()
  throw new Error('server did not start')
})
after(() => proc?.kill())

async function liveTools() {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, anonymous: true })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  return (await client.listTools()).tools
}

test('200, JSON, CORS *, cacheable', async () => {
  const r = await fetch(base + PATH)
  assert.equal(r.status, 200)
  assert.match(r.headers.get('content-type') || '', /^application\/json/)
  assert.equal(r.headers.get('access-control-allow-origin'), '*')
  assert.match(r.headers.get('cache-control') || '', /max-age/)
})

test('serverInfo name+version come from the live server', async () => {
  const card = await (await fetch(base + PATH)).json() as any
  assert.equal(card.serverInfo.name, 'webability')
  assert.equal(card.serverInfo.version, MCP_VERSION)
})

test('tools match the hosted tools/list exactly (names, descriptions, schemas, annotations)', async () => {
  const card = await (await fetch(base + PATH)).json() as any
  const live = await liveTools()
  assert.ok(live.length > 5)
  assert.deepEqual(card.tools.map((t: any) => t.name), live.map((t) => t.name))
  for (const t of live) {
    const c = card.tools.find((x: any) => x.name === t.name)
    assert.equal(c.description, t.description, t.name)
    assert.deepEqual(c.inputSchema, t.inputSchema, t.name)
    assert.deepEqual(c.annotations, t.annotations, t.name)
  }
})

test('icon, homepage, description, auth', async () => {
  const card = await (await fetch(base + PATH)).json() as any
  const meta = JSON.parse(readFileSync(join(import.meta.dirname, '../server.json'), 'utf8'))
  assert.match(card.iconUrl, /^https:\/\/www\.webability\.io\//)
  assert.equal(card.homepage, 'https://www.webability.io/mcp')
  assert.equal(card.description, meta.description)
  assert.equal(card.authentication.required, false)
  assert.deepEqual(card.authentication.schemes, ['oauth2'])
  assert.match(card.authentication.description, /anonymous/i)
  assert.deepEqual(card.resources, [])
  assert.deepEqual(card.prompts, [])
})

test('POST refused; OPTIONS ok', async () => {
  assert.ok([404, 405].includes((await fetch(base + PATH, { method: 'POST', body: '{}' })).status))
  assert.equal((await fetch(base + PATH, { method: 'OPTIONS' })).status, 204)
})
