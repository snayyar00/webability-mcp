/**
 * Security headers (#1457 item 4): every response from the hosted transport —
 * JSON, CORS preflight, the plain-text challenge, the root redirect — carries
 * nosniff / DENY / no-referrer / a locked-down CSP.
 *
 * The OAuth HTML pages are the deliberate exception: they are their own
 * documents with inline <style>/<script>, so their CSP must still allow what
 * they ship with (otherwise the sign-in page renders blank and never starts).
 *
 * Fully offline: src/http.ts runs in a child process pointed at an API URL that
 * answers nothing, so no request here reaches a real service. Readiness is the
 * process's own "listening on" line, not a poll interval.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, test } from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))

/** Headers every response gets, whatever its content type. */
const PLAIN_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
}

let child: ChildProcess | undefined
let base = ''

function assertPlainHeaders(res: Response) {
  for (const [name, value] of Object.entries(PLAIN_HEADERS)) {
    assert.equal(res.headers.get(name), value, `${name} missing on ${res.url}`)
  }
}

function assertLockedCsp(res: Response) {
  const csp = res.headers.get('content-security-policy')
  assert.ok(csp, `Content-Security-Policy missing on ${res.url}`)
  assert.match(csp, /default-src 'none'/)
  assert.match(csp, /frame-ancestors 'none'/)
}

/** A port nothing else holds, so the child's listen() cannot collide. */
async function freePort(): Promise<number> {
  const probe = createServer()
  const { promise: listening, resolve: onListening } = Promise.withResolvers<void>()
  probe.listen(0, '127.0.0.1', onListening)
  await listening
  const port = (probe.address() as AddressInfo).port
  const { promise: closed, resolve: onClosed } = Promise.withResolvers<void>()
  probe.close(onClosed)
  await closed
  return port
}

/**
 * `node --import tsx` rather than the tsx CLI: the CLI is a wrapper process, so
 * killing it leaves the real server listening and the test run hangs.
 */
function spawnServer(port: number): ChildProcess {
  return spawn(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'http.ts')], {
    env: {
      ...process.env,
      PORT: String(port),
      MCP_PUBLIC_URL: `http://127.0.0.1:${port}`,
      OAUTH_SIGNING_SECRET: 'security-headers-test-secret-0123456789abcdef',
      OPENAI_APPS_CHALLENGE_TOKEN: 'challenge-token',
      WEBABILITY_API_URL: 'http://127.0.0.1:9',
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
}

before(async () => {
  const port = await freePort()
  base = `http://127.0.0.1:${port}`
  const proc = spawnServer(port)
  child = proc
  const stderr: string[] = []
  const { promise: ready, resolve: onReady, reject: onBootFailure } = Promise.withResolvers<void>()
  proc.stderr?.on('data', (chunk: Buffer) => {
    const text = String(chunk)
    stderr.push(text)
    if (text.includes('listening on')) onReady()
  })
  proc.on('exit', (code) => onBootFailure(new Error(`http.ts exited (${code}) before listening:\n${stderr.join('')}`)))
  // The boot may also fail via assertSigningSecret, which prints before exiting.
  proc.on('error', onBootFailure)
  await ready
})

after(() => {
  child?.kill('SIGKILL')
})

test('JSON responses carry the security headers (GET /health)', async () => {
  const res = await fetch(`${base}/health`)
  assert.equal(res.status, 200)
  assertPlainHeaders(res)
  assertLockedCsp(res)
})

test('a successful initialize on /mcp carries them (SDK writes that status line)', async () => {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'security-headers', version: '0' } },
    }),
  })
  assert.equal(res.status, 200)
  assertPlainHeaders(res)
  assertLockedCsp(res)
  // The header set must not have cost us the transport: a real MCP answer.
  assert.match(res.headers.get('content-type') || '', /application\/json/)
  const body = (await res.json()) as { result?: { serverInfo?: { name?: string } } }
  assert.ok(body.result, `initialize returned ${JSON.stringify(body)}`)
})

test('an unauthenticated POST /mcp carries them too (400 parse error)', async () => {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: '{',
  })
  assert.equal(res.status, 400)
  assertPlainHeaders(res)
  assertLockedCsp(res)
})

test('the CORS preflight keeps its CORS headers and gains the security ones', async () => {
  const res = await fetch(`${base}/mcp`, { method: 'OPTIONS' })
  assert.equal(res.status, 204)
  assert.equal(res.headers.get('access-control-allow-origin'), '*', 'existing CORS must survive')
  assert.match(res.headers.get('access-control-allow-headers') || '', /Authorization/)
  assertPlainHeaders(res)
  assertLockedCsp(res)
})

test('the plain-text challenge response and the root redirect carry them', async () => {
  const challenge = await fetch(`${base}/.well-known/openai-apps-challenge`)
  assert.equal(challenge.status, 200)
  assert.equal(challenge.headers.get('content-type'), 'text/plain; charset=utf-8')
  assertPlainHeaders(challenge)
  assertLockedCsp(challenge)

  const root = await fetch(`${base}/`, { redirect: 'manual' })
  assert.equal(root.status, 302)
  assert.equal(root.headers.get('location'), 'https://www.webability.io/docs/mcp')
  assertPlainHeaders(root)
  assertLockedCsp(root)
})

test('the OAuth pages still allow their own inline styles, script and fetch', async () => {
  const reg = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['https://client.example/cb'], client_name: 'Security Headers Test' }),
  })
  assert.equal(reg.status, 201)
  const { client_id } = (await reg.json()) as { client_id: string }

  const q = new URLSearchParams({
    client_id,
    redirect_uri: 'https://client.example/cb',
    response_type: 'code',
    state: 'state-xyz',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
  })
  const page = await fetch(`${base}/authorize?${q}`)
  assert.equal(page.status, 200)
  assert.equal(page.headers.get('content-type'), 'text/html; charset=utf-8')

  // The page is inline-only: if the CSP forbids these, sign-in never starts.
  const html = await page.text()
  assert.match(html, /<style>/)
  assert.match(html, /<script>/)

  const csp = page.headers.get('content-security-policy')
  assert.ok(csp, 'Content-Security-Policy missing on the authorize page')
  assert.match(csp, /style-src [^;]*'unsafe-inline'/)
  assert.match(csp, /script-src [^;]*'unsafe-inline'/)
  assert.match(csp, /connect-src 'self'/, 'the page POSTs to /authorize/start')
  assert.match(csp, /frame-ancestors 'none'/)

  // Clickjacking / sniffing / referrer protection still applies to HTML.
  assertPlainHeaders(page)
})

test('the invalid-request page is a page too, so it gets the HTML policy', async () => {
  const res = await fetch(`${base}/authorize?client_id=bogus`)
  assert.equal(res.status, 400)
  assert.match(res.headers.get('content-type') || '', /text\/html/)
  const csp = res.headers.get('content-security-policy')
  assert.ok(csp)
  assert.match(csp, /style-src [^;]*'unsafe-inline'/, 'that page styles its own <p> inline')
  assertPlainHeaders(res)
})
