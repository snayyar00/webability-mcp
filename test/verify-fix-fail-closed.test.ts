/**
 * M0 (scanner-agent DESIGN §2): verify_fix fails closed. A pass needs a
 * selector that matched at least one element AND a criterion the sync engines
 * can actually check. Same input -> same verdict.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'
// No judge: the default local install without a key. A needsReview finding is then dropped, never judged.
process.env.WEBABILITY_JUDGE = 'off'
delete process.env.OPENROUTER_API_KEY

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const PAGE = `<!doctype html><html lang="en"><head><title>Verify</title></head><body style="background:#fff;color:#000">
<main><h1>Verify</h1>
  <img id="fixed" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="Company logo" width="40" height="40">
  <img id="broken" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" width="40" height="40">
  <div id="wrap"><img class="m" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="ok one" width="40" height="40">
  <img class="m" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" width="40" height="40"></div>
</main></body></html>`

// Separate pages: unresolvable findings elsewhere on a page are kept on purpose
// (scope.ts fails closed), so shadow / iframe content must not share the page
// with the control that has to verify true.
const SHADOW_PAGE = `<!doctype html><html lang="en"><head><title>S</title></head><body><main><h1>S</h1><div id="host"></div></main>
<script>document.getElementById('host').attachShadow({ mode: 'open' }).innerHTML = '<img id="shadowimg" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" width="40" height="40">'</script></body></html>`
const FRAME_PAGE = `<!doctype html><html lang="en"><head><title>F</title></head><body><main><h1>F</h1>
<iframe id="frame" title="inner" srcdoc="<img id='inframe' src='data:image/gif;base64,R0lGODlhAQABAAAAACw=' width='40' height='40'>"></iframe></main></body></html>`

// Elements whose only finding is needsReview (broken skip link 2.4.1, decorative image with a title 1.1.1).
const UNDECIDED_PAGE = `<!doctype html><html lang="en"><head><title>U</title></head><body>
<a id="skip" href="#nowhere">Skip to content</a>
<nav><a href="/a">A</a> <a href="/b">B</a> <a href="/c">C</a> <a href="/d">D</a></nav>
<main><h1>U</h1><img id="deco" alt="" title="Company logo" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" width="40" height="40"></main></body></html>`

// White text on a dark gradient: the pixel resolver measures it as a pass. No
// judge is needed for that verdict, so verify_fix must not refuse it.
const GRADIENT_PAGE = `<!doctype html><html lang="en"><head><title>G</title></head><body><main><h1>G</h1>
<h2 id="grad" style="color:#fff;background:linear-gradient(#000,#1a1a1a);padding:8px">White on a dark gradient</h2></main></body></html>`

let http: HttpServer
let url = ''
before(async () => {
  http = createHttpServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(req.url === '/gradient' ? GRADIENT_PAGE : req.url === '/undecided' ? UNDECIDED_PAGE : req.url === '/shadow' ? SHADOW_PAGE : req.url === '/frame' ? FRAME_PAGE : PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

async function verifyOnce(args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'verify_fix', arguments: { url, ...args } }, undefined, { timeout: 180_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const json = JSON.parse(text.match(/```json\n([\s\S]*)\n```/)![1]!)
  return { text, json, structured: r.structuredContent }
}

/** Run twice: the verdict (and reason) must be identical. */
async function verify(args: Record<string, unknown>) {
  const a = await verifyOnce(args)
  const b = await verifyOnce(args)
  assert.equal(a.json.verified, b.json.verified, 'verdict is not deterministic')
  assert.equal(a.json.reason, b.json.reason, 'reason is not deterministic')
  assert.equal(a.json.remainingCount, b.json.remainingCount, 'remainingCount is not deterministic')
  return a
}

test('c22: 0-match selector -> verified:false, "selector matched no elements"', async () => {
  const { text, json } = await verify({ selector: 'a.skip-link', wcag: '2.4.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-found')
  assert.equal(json.reasonText, 'selector matched no elements')
  assert.doesNotMatch(text, /^VERIFIED/m)
})

test('invalid selector syntax -> verified:false, no throw', async () => {
  const { text, json } = await verify({ selector: 'img[[bad', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'invalid-selector')
})

test('selector on an element that still fails -> false', async () => {
  const { text, json } = await verify({ selector: '#broken', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
  assert.ok(json.remainingCount >= 1)
})

test('selector on a fixed element -> true', async () => {
  const { text, json } = await verify({ selector: '#fixed', wcag: '1.1.1' })
  assert.equal(json.verified, true, text)
})

test('several matches, one still failing -> false', async () => {
  const { text, json } = await verify({ selector: '#wrap', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
})

test('criterion outside the sync coverage set -> false, "not checked by any WebAbility tool"', async () => {
  const { text, json } = await verify({ selector: '#fixed', wcag: '3.1.3' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-verifiable')
  assert.equal(json.reasonText, 'not checked by any WebAbility tool')
  assert.doesNotMatch(text, /deep audit|human review/i)
  assert.doesNotMatch(text, /^VERIFIED/m)
})

test('selector inside shadow DOM (>>>) -> explicit refusal, not a silent true', async () => {
  const { text, json } = await verify({ url: url + 'shadow', selector: '#host >>> #shadowimg', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'unsupported-selector')
  assert.match(json.reasonText, /shadow DOM|iframe/)
})

test('selector inside an iframe -> verified:false, never a silent true', async () => {
  const { text, json } = await verify({ url: url + 'frame', selector: '#inframe', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-found')
  assert.match(text, /iframe/)
})

test('2.1.2: no engine checks it (axe has no rule, no native detector maps to it) -> not-verifiable, never a pass by absence', async () => {
  const { text, json } = await verify({ selector: '#fixed', wcag: '2.1.2' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-verifiable')
})

test('criteria no engine can fail (3.2.3, 3.2.4, 1.2.5, 2.4.9, 2.4.5) -> not-verifiable', async () => {
  for (const wcag of ['3.2.3', '3.2.4', '1.2.5', '2.4.9', '2.4.5']) {
    const { text, json } = await verify({ selector: '#fixed', wcag })
    assert.equal(json.verified, false, text)
    assert.equal(json.reason, 'not-verifiable')
  }
})

test('partial criterion id "1.1" keeps the prefix filter: broken -> false, fixed -> true', async () => {
  const broken = await verify({ selector: '#broken', wcag: '1.1' })
  assert.equal(broken.json.verified, false, broken.text)
  assert.notEqual(broken.json.reason, 'not-verifiable')
  const fixed = await verify({ selector: '#fixed', wcag: '1.1' })
  assert.equal(fixed.json.verified, true, fixed.text)
})

test('bogus numeric ids (9.9, 1.1.1.1) -> not-verifiable, never a pass by absence', async () => {
  for (const wcag of ['9.9', '1.1.1.1']) {
    const { text, json } = await verify({ selector: '#broken', wcag })
    assert.equal(json.verified, false, text)
    assert.equal(json.reason, 'not-verifiable')
  }
})

test('">>>" inside a quoted attribute value is not a piercing selector', async () => {
  const { json } = await verify({ selector: 'img[alt="previous >>> next"]', wcag: '1.1.1' })
  assert.notEqual(json.reason, 'unsupported-selector')
  assert.equal(json.reason, 'not-found')
})

test('mcp uses the core coverage function (no local copy)', async () => {
  const core = await import('@webability/core')
  assert.equal(typeof core.criterionVerifiability, 'function')
  const { existsSync } = await import('node:fs')
  assert.equal(existsSync(new URL('../src/verifyCoverage.ts', import.meta.url)), false)
})

test('judge did not run: a needsReview-only skip link in scope is not-verifiable, never VERIFIED (2.4.1)', async () => {
  const { text, json } = await verifyOnce({ url: url + 'undecided', selector: '#skip', wcag: '2.4.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-verifiable')
  assert.match(json.reasonText, /judge/i)
  assert.doesNotMatch(text, /^VERIFIED/m)
})

test('judge did not run: a decorative image with a title in scope is not-verifiable (1.1.1)', async () => {
  const { text, json } = await verifyOnce({ url: url + 'undecided', selector: '#deco', wcag: '1.1.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-verifiable')
})

test('judge did not run, but the undecided element is for another criterion: still verifies', async () => {
  const { text, json } = await verifyOnce({ url: url + 'undecided', selector: '#deco', wcag: '4.1.2' })
  assert.equal(json.verified, true, text)
})

test('every refusal carries a verify card (structuredContent), not just not-found', async () => {
  for (const [args, reason] of [
    [{ selector: '#fixed', wcag: '3.1.3' }, 'not-verifiable'],
    [{ selector: '#host >>> #x', wcag: '1.1.1' }, 'unsupported-selector'],
    [{ url: url + 'undecided', selector: '#skip', wcag: '2.4.1' }, 'not-verifiable'],
  ] as const) {
    const { structured, json } = await verifyOnce(args)
    assert.equal(structured?.kind, 'verify', JSON.stringify(json))
    assert.equal(structured?.verified, false)
    assert.equal(structured?.reason, reason)
  }
})

test('measured contrast pass on a gradient verifies without a judge (1.4.3)', async () => {
  const { text, json } = await verify({ url: `${url}gradient`, selector: '#grad', wcag: '1.4.3' })
  assert.equal(json.verified, true, text)
  assert.doesNotMatch(text, /only the AI judge can settle/)
})
