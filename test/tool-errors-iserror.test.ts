/**
 * A refused or failed tool call must set `isError: true`. Without it an agent
 * reads "start_audit: … no `tunnel_secret` was passed" as a successful result
 * and carries on (dogfood 2026-09-26: both tunnel refusals came back
 * isError:false).
 *
 * Drives the real createServer({ remote: true }) with fetch stubbed.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { afterEach, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const TUNNEL_URL = 'https://tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/digest.html'
const CONTEXT = 'Verifying that refused and failed tool calls are flagged as errors to the calling agent.'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

function stubFetch(status: number, body: unknown) {
  globalThis.fetch = (async (input: any) => {
    const url = String(input)
    if (url.includes('/cli/')) return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
    return new Response(null, { status: 204 })
  }) as typeof fetch
}

async function call(name: string, args: Record<string, unknown>, remote = true) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name, arguments: { context: CONTEXT, llm_model: 'test', ...args } })
  return { isError: res.isError === true, text: res.content.map((c: any) => c.text).join('\n') }
}

test('start_audit on a tunnel URL with no secret is an error', async () => {
  stubFetch(200, { id: 1, status: 'pending' })
  const res = await call('start_audit', { url: TUNNEL_URL })
  assert.match(res.text, /no `tunnel_secret` was passed/)
  assert.equal(res.isError, true)
})

test('visual_audit on a tunnel URL with no secret is an error', async () => {
  const res = await call('visual_audit', { url: TUNNEL_URL })
  assert.match(res.text, /no `tunnel_secret` was passed/)
  assert.equal(res.isError, true)
})

test('an API failure is an error', async () => {
  stubFetch(500, { error: 'boom' })
  const res = await call('start_audit', { url: 'https://example.com' })
  assert.match(res.text, /start_audit failed \(500\)/)
  assert.equal(res.isError, true)
})

test('bad input is an error', async () => {
  const res = await call('check_color_contrast', { foreground: 'notacolor', background: 'alsonot' })
  assert.match(res.text, /Could not parse colors/)
  assert.equal(res.isError, true)
})

test('a queued audit is not an error', async () => {
  stubFetch(200, { id: 7, status: 'pending' })
  const res = await call('start_audit', { url: 'https://example.com' })
  assert.match(res.text, /Audit #7 queued/)
  assert.equal(res.isError, false)
})

test('a hosted scan of a private address is an error', async () => {
  const res = await call('scan_page', { url: 'http://127.0.0.1:8080/' })
  assert.equal(res.isError, true, res.text)
})

test('start_audit on localhost is an error', async () => {
  const res = await call('start_audit', { url: 'http://localhost:3000/' })
  assert.equal(res.isError, true, res.text)
})

test('a Full tool on the local Lite server is an error', async () => {
  const res = await call('start_audit', { url: 'https://example.com' }, false)
  assert.equal(res.isError, true, res.text)
})

/**
 * Inverted on purpose: a regex for "error-shaped" text missed nine refusals
 * (a comma in "runs server-side, so it cannot reach", "requires a WebAbility
 * account", blockedUrlMessage(...)). Every plain `return { content: … }` must
 * instead be a reviewed RESULT; anything else goes through toolError().
 */
const RESULT_PREFIXES = [
  'text: `Branded accessibility report written to',
  "text: '```json\\n' + JSON.stringify(stored",
  'text: `No scans logged yet',
  'text: `Framework: ',
  'text: `AI service unavailable (${res.status}). Deterministic fallback',
  'text: `# Visual Audit: ',
  'text: `No source files under ',
  "text: lines.join('\\n')",
  // get_rules: a WCAG criterion no automated rule covers is an answer, not a failure.
  'text: `0 rules: no rule covers',
]

test('every plain one-line text return is a reviewed result, not a refusal', () => {
  const src = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'server.ts'), 'utf8')
  const unreviewed = src
    .split('\n')
    .map((line, i) => ({ line, n: i + 1 }))
    .filter(({ line }) => /return \{ content: \[\{ type: 'text', text: /.test(line))
    .filter(({ line }) => !RESULT_PREFIXES.some((p) => line.includes(p)))
  assert.deepEqual(
    unreviewed.map(({ n, line }) => `${n}: ${line.trim().slice(0, 100)}`),
    [],
    'a refusal or failure must use toolError(); a real result must be added to RESULT_PREFIXES',
  )
})
