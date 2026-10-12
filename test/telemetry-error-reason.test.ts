/**
 * Failed tool calls report WHY they failed. Before this, mcp_scan_events had
 * ok=false and nothing else, so 521 failed hosted scan_page calls in 30 days
 * could not be explained. The reason is a stable code plus a short scrubbed
 * message ("fetch_failed: 500"), at most 300 chars, never page content,
 * query strings, tokens or emails. Success events carry no `error` at all.
 */
import { mkdtempSync } from 'node:fs'
import { homedir, platform, tmpdir } from 'node:os'
import { join } from 'node:path'

// Playwright finds its browsers under $HOME: pin the real cache before HOME moves.
process.env.PLAYWRIGHT_BROWSERS_PATH ??= platform() === 'darwin' ? join(homedir(), 'Library/Caches/ms-playwright') : join(homedir(), '.cache/ms-playwright')
process.env.HOME = mkdtempSync(join(tmpdir(), 'wa-telemetry-home-'))
process.env.WEBABILITY_SCAN_LOG = 'off'
delete process.env.WEBABILITY_SCAN_TELEMETRY

import assert from 'node:assert/strict'
import { afterEach, beforeEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import { classifyToolError, sanitizeTelemetryError } from '../src/telemetry.ts'

const realFetch = globalThis.fetch
let events: any[] = []
beforeEach(() => {
  events = []
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(input)
    if (url.endsWith('/mcp/scan-events')) {
      events.push(JSON.parse(String(init?.body)))
      return new Response(null, { status: 204 })
    }
    if (url.includes('/cli/')) {
      return new Response('<html>secret page content for jane@corp.test</html>', { status: 500 })
    }
    return new Response(null, { status: 204 })
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

async function call(name: string, args: Record<string, unknown>, opts: Record<string, unknown> = {}) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(opts as any).connect(s), cl.connect(c)])
  const r: any = await cl.callTool({ name, arguments: args }, undefined, { timeout: 120_000 })
  await cl.close()
  const last = events[events.length - 1]
  return { r, event: last }
}
const REMOTE = { remote: true, authToken: 'tok' }
const TUNNEL = 'https://tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/digest.html'

test('sanitize: truncates to 300 chars', () => {
  assert.equal(sanitizeTelemetryError('word '.repeat(300)).length, 300)
})

test('sanitize: strips query strings, hashes, bearer values, emails and long tokens', () => {
  const out = sanitizeTelemetryError(
    'fetch_failed: https://x.test/p?token=abc&email=a@b.com#frag Bearer abc.def-ghi jane@corp.test ' + 'a1'.repeat(20) + ' secret=hunter2',
  )
  assert.doesNotMatch(out, /token=abc|a@b\.com|#frag|abc\.def|jane@corp|a1a1a1a1|hunter2/)
  assert.match(out, /https:\/\/x\.test\/p/)
})

test('classify: stable codes', () => {
  assert.equal(classifyToolError('Error: url is required'), 'invalid_args: Error: url is required')
  assert.equal(classifyToolError('visual_audit needs a free WebAbility account, and this connection is not signed in.'), 'auth_required')
  assert.equal(classifyToolError('Visual audit failed (502): <html>page body</html>'), 'fetch_failed: 502')
  assert.equal(classifyToolError('start_audit is rate-limited (too many audits queued). Wait and retry.'), 'rate_limited')
  assert.match(classifyToolError('Scan failed: page.goto: Timeout 30000ms exceeded.'), /^timeout/)
  assert.match(classifyToolError('Scan failed: page.goto: net::ERR_NAME_NOT_RESOLVED at https://nope.test/?a=1'), /^navigation_failed: .*ERR_NAME_NOT_RESOLVED/)
  assert.doesNotMatch(classifyToolError('Scan failed: page.goto: net::ERR_NAME_NOT_RESOLVED at https://nope.test/?a=1'), /a=1/)
  assert.match(classifyToolError('BLOCKED: https://x.test/ was not actually scanned. Cloudflare challenge.'), /^blocked: /)
  assert.match(classifyToolError('Scan failed: something odd'), /^exception: something odd/)
  assert.match(classifyToolError('Unknown tool: nope'), /^invalid_args/)
})

test('classify: an HTTP failure whose body mentions timeout keeps only the status', () => {
  assert.equal(classifyToolError('start_audit failed (500): upstream timeout for customer acme-corp'), 'fetch_failed: 500')
  assert.equal(classifyToolError('Visual audit failed (502): request timed out, resolves to 10.0.0.1'), 'fetch_failed: 502')
})

test('sanitize: absolute local filesystem paths are redacted, URL paths are kept', () => {
  const posix = sanitizeTelemetryError("EACCES: permission denied, open '/home/alice/client-name/report.pdf'")
  assert.doesNotMatch(posix, /alice|client-name/)
  assert.match(posix, /EACCES/)
  assert.doesNotMatch(sanitizeTelemetryError('ENOENT: no such file /Users/sidharth/Documents/Acme/x.pdf'), /sidharth|Acme/)
  assert.doesNotMatch(sanitizeTelemetryError('open C:\\Users\\bob\\proj\\out.pdf failed'), /bob|proj/)
  assert.equal(sanitizeTelemetryError('open ~/clients/acme/out.pdf failed'), 'open [path] failed')
  assert.equal(sanitizeTelemetryError('fetch_failed: https://www.webability.io/blog/post'), 'fetch_failed: https://www.webability.io/blog/post')
  assert.equal(classifyToolError("generate_report_pdf failed: EACCES: permission denied, open '/home/alice/client-name/report.pdf'").includes('alice'), false)
})

test('every failure path sets error (<= 300 chars); the success path has none', async () => {
  const failing: Array<[string, Record<string, unknown>, Record<string, unknown>?, RegExp?]> = [
    ['scan_page', {}, undefined, /^invalid_args/],
    ['flow_scan', {}, undefined, /^invalid_args/],
    ['scan_html', {}, undefined, /^invalid_args/],
    ['check_aria', {}, undefined, /^invalid_args/],
    ['verify_fix', {}, undefined, /^invalid_args/],
    ['check_color_contrast', { foreground: 'notacolor', background: 'alsonot' }, undefined, /^invalid_args/],
    ['scan_page', { url: 'http://127.0.0.1:8080/' }, REMOTE, /^blocked_url/],
    ['start_audit', { url: 'https://www.webability.io/' }, REMOTE, /^fetch_failed: 500/],
    ['visual_audit', { url: TUNNEL }, REMOTE, /^invalid_args/],
    ['visual_audit', { url: 'https://www.webability.io/' }, { remote: true, anonymous: true }, /^auth_required/],
    ['add_site', { url: '' }, REMOTE, /^invalid_args/],
    ['scan_page', { url: 'http://127.0.0.1:1/?token=abc' }, undefined, /^navigation_failed|^timeout/],
  ]
  for (const [tool, args, opts, re] of failing) {
    const { event } = await call(tool, args, opts)
    assert.ok(event, `${tool}: event sent`)
    assert.equal(event.ok, false, `${tool} ${JSON.stringify(args)}`)
    assert.equal(typeof event.error, 'string', `${tool}: error present`)
    assert.ok(event.error.length > 0 && event.error.length <= 300, `${tool}: length`)
    if (re) assert.match(event.error, re, tool)
    assert.doesNotMatch(event.error, /token=abc|jane@corp|secret page content/, `${tool}: scrubbed`)
  }
})

test('success path sends no error field', async () => {
  const { event } = await call('check_color_contrast', { foreground: '#767676', background: '#ffffff' })
  assert.equal(event.ok, true)
  assert.equal('error' in event, false)
})

test('target query string is scrubbed and error carries no token (https://x.test/p?token=abc)', async () => {
  const { event } = await call('scan_page', { url: 'https://x.test/p?token=abc' }, REMOTE)
  assert.equal(event.target, 'https://x.test/p')
  if (event.ok === false) assert.doesNotMatch(String(event.error), /token=abc/)
})
