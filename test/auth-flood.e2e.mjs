#!/usr/bin/env node
/**
 * E2E for sign-in flood limits (#201). Each anonymous POST /authorize/start
 * mints a device code on the platform API, and each unknown bearer token on
 * /mcp costs a platform whoami call. Both were unthrottled (150/150 mints).
 * Now: per client IP, /authorize/start and failed token checks are capped
 * (429 + Retry-After, no upstream call). Normal sign-in, valid tokens and
 * other IPs are unaffected; a valid token is never counted.
 *
 * Fully offline. Run: node test/auth-flood.e2e.mjs
 */
import { createServer } from 'http'
import { spawn } from 'child_process'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + String(detail)}`)
  if (!cond) failures++
}

const VALID = ['wa_valid_token_one', 'wa_valid_token_two']
let deviceCodeCalls = 0
let whoamiCalls = 0
const mockApi = createServer((req, res) => {
  req.resume()
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json')
    if (req.url === '/cli/device-code') {
      deviceCodeCalls++
      res.end(JSON.stringify({ deviceCode: `dc${deviceCodeCalls}`, userCode: 'ABCD-1234', verificationUrl: 'https://app.webability.io/cli/verify?code=ABCD-1234' }))
      return
    }
    if (req.url === '/cli/whoami') {
      whoamiCalls++
      res.statusCode = VALID.some((t) => req.headers.authorization === `Bearer ${t}`) ? 200 : 401
      res.end('{}')
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
})
await new Promise((r) => mockApi.listen(0, '127.0.0.1', r))

const PORT = 22000 + Math.floor(Math.random() * 2000)
const BASE = `http://127.0.0.1:${PORT}`
const LIMIT = 3
const child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
  env: {
    ...process.env,
    PORT: String(PORT),
    WEBABILITY_API_URL: `http://127.0.0.1:${mockApi.address().port}`,
    MCP_PUBLIC_URL: BASE,
    OAUTH_SIGNING_SECRET: 'auth-flood-test-secret-0123456789abcdef',
    TRUST_CF_CONNECTING_IP: 'true',
    ANON_AUTH_START_PER_HOUR: String(LIMIT),
    BAD_TOKEN_PER_HOUR: String(LIMIT),
  },
  stdio: ['ignore', 'inherit', 'inherit'],
})
for (let i = 0; i < 50; i++) {
  try { await fetch(`${BASE}/health`); break } catch { await new Promise((r) => setTimeout(r, 200)) }
}

const ip = (a) => ({ 'cf-connecting-ip': a })
const json = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }

async function register() {
  const r = await fetch(`${BASE}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'flood', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'], token_endpoint_auth_method: 'none' }) })
  return (await r.json()).client_id
}
async function start(clientId, from) {
  return fetch(`${BASE}/authorize/start`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...ip(from) },
    body: JSON.stringify({ client_id: clientId, redirect_uri: 'https://claude.ai/api/mcp/auth_callback', state: 's', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' }),
  })
}
const listTools = (token, from) => fetch(`${BASE}/mcp`, { method: 'POST', headers: { ...json, ...ip(from), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) })

try {
  const clientId = await register()

  // --- /authorize/start flood
  const statuses = []
  for (let i = 0; i < LIMIT; i++) statuses.push((await start(clientId, '198.51.100.10')).status)
  check(`first ${LIMIT} sign-in starts from one IP → 200`, statuses.every((s) => s === 200), statuses)
  const mintsBefore = deviceCodeCalls
  const flooded = await start(clientId, '198.51.100.10')
  check('the next start from that IP → 429 + Retry-After', flooded.status === 429 && !!flooded.headers.get('retry-after'), `${flooded.status} ${flooded.headers.get('retry-after')}`)
  check('a refused start mints no device code upstream', deviceCodeCalls === mintsBefore, deviceCodeCalls - mintsBefore)
  check('another IP can still start sign-in', (await start(clientId, '198.51.100.11')).status === 200)

  // --- valid token, cached before any flood
  check('valid token → 200', (await listTools(VALID[0], '198.51.100.20')).status === 200)

  // --- garbage-token flood
  const bad = []
  for (let i = 0; i < LIMIT; i++) bad.push((await listTools(`garbage-${i}`, '198.51.100.20')).status)
  check(`first ${LIMIT} garbage tokens → 401`, bad.every((s) => s === 401), bad)
  const whoamiBefore = whoamiCalls
  const badFlood = await listTools('garbage-final', '198.51.100.20')
  check('the next garbage token from that IP → 429 + Retry-After', badFlood.status === 429 && !!badFlood.headers.get('retry-after'), `${badFlood.status}`)
  check('a refused garbage token costs no whoami call', whoamiCalls === whoamiBefore, whoamiCalls - whoamiBefore)

  // --- legit paths after the flood
  check('the cached valid token from the flooded IP → 200', (await listTools(VALID[0], '198.51.100.20')).status === 200)
  check('anonymous (no token) from the flooded IP → 200', (await listTools(undefined, '198.51.100.20')).status === 200)
  check('a new valid token from another IP → 200', (await listTools(VALID[1], '198.51.100.21')).status === 200)
  check('a garbage token from another IP still gets its 401', (await listTools('garbage-other', '198.51.100.22')).status === 401)

  // --- valid tokens are never counted
  for (let i = 0; i < LIMIT * 3; i++) await listTools(VALID[1], '198.51.100.30')
  check('many valid-token calls from one IP are never throttled', (await listTools(VALID[1], '198.51.100.30')).status === 200)
} finally {
  child.kill()
  mockApi.close()
}

console.log(failures ? `\n${failures} FAILED` : '\nALL PASS')
process.exit(failures ? 1 : 0)
