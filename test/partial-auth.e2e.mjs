#!/usr/bin/env node
/**
 * E2E for partial auth: the hosted /mcp starts AUTHLESS for the free tools,
 * and an anonymous call to an account tool (start_audit / get_audit /
 * visual_audit) gets an isError tool result with the sign-in steps — not an
 * HTTP 401, which makes Claude Code drop every tool. /mcp/auth is the path
 * that answers 401 + WWW-Authenticate so a client signs in on connect.
 * Anonymous callers are rate-limited per IP; authenticated callers are not.
 *
 * Fully offline. Run: node test/partial-auth.e2e.mjs
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

// mock platform API: whoami + ai-fix
const USER_TOKEN = 'wa_live_partial_auth_token'
const mockApi = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json')
    if (req.url === '/cli/whoami') {
      res.statusCode = (req.headers.authorization || '') === `Bearer ${USER_TOKEN}` ? 200 : 401
      res.end('{}')
      return
    }
    if (req.url === '/cli/ai-fix') {
      res.end(JSON.stringify({ alternatives: [{ label: 'x', previewCss: 'color:#333' }] }))
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
})
await new Promise((r) => mockApi.listen(0, '127.0.0.1', r))

const PORT = 18000 + Math.floor(Math.random() * 2000)
const BASE = `http://127.0.0.1:${PORT}`
const child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
  env: {
    ...process.env,
    PORT: String(PORT),
    WEBABILITY_API_URL: `http://127.0.0.1:${mockApi.address().port}`,
    MCP_PUBLIC_URL: BASE,
    OAUTH_SIGNING_SECRET: 'partial-auth-test-secret-0123456789',
    WEBABILITY_API_KEY: 'operator-key-must-never-serve-anon',
    ANON_AI_PER_HOUR: '2', // tiny cap so the test can trip it
  },
  stdio: ['ignore', 'inherit', 'inherit'],
})
for (let i = 0; i < 50; i++) {
  try { await fetch(`${BASE}/health`); break } catch { await new Promise((r) => setTimeout(r, 200)) }
}

function rpc(method, params, id = 1) {
  return { jsonrpc: '2.0', method, id, params }
}
async function post(body, headers = {}) {
  return fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify(body),
  })
}
const INIT = rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'pa', version: '0' } })

try {
  // 1. anonymous initialize + tools/list work (authless start)
  const init = await post(INIT)
  check('anonymous initialize → 200', init.status === 200, init.status)
  const list = await post(rpc('tools/list', {}))
  check('anonymous tools/list → 200', list.status === 200, list.status)

  // 2. anonymous free tool works (get_rules is local data, no browser)
  const rules = await post(rpc('tools/call', { name: 'get_rules', arguments: { tags: ['wcag2aa'] } }))
  check('anonymous free tool (get_rules) → 200', rules.status === 200, rules.status)

  // 3. anonymous account tool → 200 isError tool result, no 401 / WWW-Authenticate
  for (const name of ['start_audit', 'get_audit', 'visual_audit']) {
    const r = await post(rpc('tools/call', { name, arguments: { url: 'https://webability.io', id: 1 } }))
    const j = await r.json().catch(() => ({}))
    check(`anonymous ${name} → 200 isError, no WWW-Authenticate`, r.status === 200 && j?.result?.isError === true && !r.headers.get('www-authenticate'), `${r.status} ${JSON.stringify(j).slice(0, 160)}`)
  }

  // 4. anonymous AI tool is rate limited (cap 2/hour in this test)
  let last
  for (let i = 0; i < 3; i++) {
    last = await post(rpc('tools/call', { name: 'generate_ai_fix', arguments: { issue: { message: 'x' }, html: '<p>x</p>', framework: 'plain-css' } }))
  }
  check('anonymous generate_ai_fix trips 429 after cap', last.status === 429 && !!last.headers.get('retry-after'), `${last.status} retry-after=${last.headers.get('retry-after')}`)

  // 5. an authenticated caller is not rate limited and can call paid tools
  const authed = await post(rpc('tools/call', { name: 'generate_ai_fix', arguments: { issue: { message: 'x' }, html: '<p>x</p>', framework: 'plain-css' } }), { authorization: `Bearer ${USER_TOKEN}` })
  check('authenticated generate_ai_fix bypasses anon cap', authed.status === 200, authed.status)

  // 6. the refusal tells a human how to sign in from their client
  const paid = await post(rpc('tools/call', { name: 'start_audit', arguments: { url: 'https://webability.io' } }))
  const body = await paid.text()
  check('account-tool refusal names the sign-in paths', /claude mcp login/.test(body) && /\/mcp\/auth/.test(body), body.slice(0, 160))
} finally {
  child.kill()
  mockApi.close()
}

console.log(failures ? `\n${failures} FAILED` : '\nALL PASS')
process.exit(failures ? 1 : 0)
