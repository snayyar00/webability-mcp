#!/usr/bin/env node
/**
 * E2E for request-body caps (#199): /mcp and the OAuth endpoints used to
 * buffer and JSON.parse any body before auth or rate limiting (256 MB
 * anonymous POST -> 200). Oversized bodies now get 413 before the body is
 * buffered and before the token is checked; normal-size requests still work.
 *
 * Fully offline. Run: node test/body-limit.e2e.mjs
 */
import { createServer } from 'http'
import { request } from 'http'
import { spawn } from 'child_process'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const here = dirname(fileURLToPath(import.meta.url))
let failures = 0
function check(name, cond, detail = '') {
  console.log(`${cond ? '  ✓' : '  ✗'} ${name}${cond ? '' : '  ' + String(detail)}`)
  if (!cond) failures++
}

// mock platform API: counts whoami calls (the token check)
let whoamiCalls = 0
const mockApi = createServer((req, res) => {
  req.resume()
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json')
    if (req.url === '/cli/whoami') whoamiCalls++
    res.statusCode = 401
    res.end('{}')
  })
})
await new Promise((r) => mockApi.listen(0, '127.0.0.1', r))

const PORT = 20000 + Math.floor(Math.random() * 2000)
const BASE = `http://127.0.0.1:${PORT}`
const child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
  env: {
    ...process.env,
    PORT: String(PORT),
    WEBABILITY_API_URL: `http://127.0.0.1:${mockApi.address().port}`,
    MCP_PUBLIC_URL: BASE,
    OAUTH_SIGNING_SECRET: 'body-limit-test-secret-0123456789abcdef',
  },
  stdio: ['ignore', 'inherit', 'inherit'],
})
for (let i = 0; i < 50; i++) {
  try { await fetch(`${BASE}/health`); break } catch { await new Promise((r) => setTimeout(r, 200)) }
}

const MB = 1024 * 1024
const json = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }
const rpc = (method, params, id = 1) => ({ jsonrpc: '2.0', method, id, params })
const INIT = rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bl', version: '0' } })

/** POST a body; `chunked` streams it with no Content-Length. Resolves with the status (or 'reset'). */
function send(path, body, { headers = json, chunked = false } = {}) {
  return new Promise((resolve) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body)
    const req = request(`${BASE}${path}`, { method: 'POST', headers: { ...headers, ...(chunked ? {} : { 'content-length': buf.length }) } }, (res) => {
      res.resume()
      res.on('end', () => resolve(res.statusCode))
    })
    req.on('error', () => resolve('reset'))
    if (chunked) {
      for (let off = 0; off < buf.length; off += 64 * 1024) req.write(buf.subarray(off, off + 64 * 1024))
      req.end()
    } else req.end(buf)
  })
}

/** A valid JSON-RPC body padded to `bytes`. */
function padded(bytes) {
  const base = JSON.stringify({ ...INIT, params: { ...INIT.params, pad: '' } })
  return JSON.stringify({ ...INIT, params: { ...INIT.params, pad: 'x'.repeat(Math.max(0, bytes - base.length)) } })
}

// The server answers 413 and closes without reading the rest of the body, so
// a client still writing can see a reset before it reads the 413. Either way
// the body was refused unbuffered; the legit checks below prove the server
// is still up.
const refused = (s) => s === 413 || s === 'reset'

try {
  // Attack blocked
  let s = await send('/mcp', padded(16 * MB))
  check('anonymous 16 MB POST /mcp (Content-Length) → 413', refused(s), s)

  s = await send('/mcp', padded(16 * MB), { chunked: true })
  check('anonymous 16 MB POST /mcp (chunked, no Content-Length) → 413', refused(s), s)

  const before = whoamiCalls
  s = await send('/mcp', padded(16 * MB), { headers: { ...json, authorization: 'Bearer garbage-token' } })
  check('16 MB POST with a token → 413 before the token is checked', refused(s) && whoamiCalls === before, `${s} whoami=${whoamiCalls - before}`)

  s = await send('/register', JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'], pad: 'x'.repeat(MB) }))
  check('1 MB POST /register → 413', refused(s), s)

  s = await send('/token', 'grant_type=authorization_code&code=' + 'x'.repeat(MB), { headers: { 'content-type': 'application/x-www-form-urlencoded' } })
  check('1 MB POST /token → 413', refused(s), s)

  s = await send('/mcp', '{"jsonrpc":"2.0",' + 'x'.repeat(2048))
  check('invalid JSON → 400 (not 500)', s === 400, s)

  // Legit path still works
  s = await send('/mcp', JSON.stringify(rpc('tools/list', {})))
  check('normal tools/list → 200', s === 200, s)

  s = await send('/mcp', padded(4 * MB))
  check('4 MB POST /mcp (large scan_html-sized body) → 200', s === 200, s)

  s = await send('/mcp', padded(2 * MB), { chunked: true })
  check('2 MB chunked POST /mcp → 200', s === 200, s)

  s = await send('/register', JSON.stringify({ redirect_uris: ['http://127.0.0.1:33418/callback'], client_name: 'body-limit' }))
  check('normal POST /register → 201', s === 201, s)
} finally {
  child.kill()
  mockApi.close()
}

console.log(failures ? `\n${failures} FAILED` : '\nALL PASS')
process.exit(failures ? 1 : 0)
