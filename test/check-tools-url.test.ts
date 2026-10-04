/**
 * Persona round 4: check_aria took only an HTML snippet and
 * check_color_contrast only a color pair, so "check the ARIA on my page" /
 * "is this button's contrast OK" meant copying markup or guessing colors.
 * Both now take `url` (+ optional `selector`) and open the page through the
 * same page-open path the other tools use; anonymous hosted calls with a url
 * count as heavy.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { anonLimitClass } from '../src/anonGate.ts'
import * as serverMod from '../src/server.ts'

const { createServer } = serverMod

const PAGE = `<!doctype html><html lang="en"><head><title>Check</title></head><body style="background:#fff">
<main>
  <h1>Check</h1>
  <div id="widget"><button aria-pressed="maybe">Toggle</button><div role="tab">tab</div></div>
  <div id="clean"><button type="button">OK</button></div>
  <p id="low" style="color:#999999">low contrast text</p>
  <div style="background:#000000"><span id="onblack" style="color:#777777">dim on black</span></div>
  <div style="background-image:linear-gradient(#000,#fff)"><span id="ongrad" style="color:#777777">on gradient</span></div>
</main></body></html>`

let http: HttpServer
let base = ''
before(async () => {
  http = createHttpServer((req, res) => {
    if (req.url === '/403') { res.writeHead(403, { 'content-type': 'text/html' }); res.end('<h1>Forbidden</h1>'); return }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE)
  })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(http.address() as any).port}`
})
after(() => http?.close())

async function client(remote = false) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(remote ? { remote: true, authToken: 'test-token' } : {}).connect(s), cl.connect(c)])
  return cl
}
async function call(name: string, args: Record<string, unknown>, remote = false) {
  const r: any = await (await client(remote)).callTool({ name, arguments: args }, undefined, { timeout: 120_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { isError: r.isError === true, text, first: String(r.content?.[0]?.text ?? ''), json: m ? JSON.parse(m[1]!) : null }
}

// ---- check_aria ----------------------------------------------------------

test('check_aria url: checks the live page', async () => {
  const r = await call('check_aria', { url: `${base}/` })
  assert.equal(r.isError, false, r.text.slice(0, 300))
  assert.ok(r.json.violations.length > 0, 'fixture has aria-pressed="maybe" and an orphan role=tab')
  assert.match(r.first, new RegExp(`on ${base}/`))
})

test('check_aria url + selector: only findings inside the selected element', async () => {
  const w = await call('check_aria', { url: `${base}/`, selector: '#widget' })
  assert.ok(w.json.violations.length > 0, w.text.slice(0, 300))
  assert.match(w.first, /within #widget/)
  const c = await call('check_aria', { url: `${base}/`, selector: '#clean' })
  assert.equal(c.isError, false)
  assert.equal(c.json.violations.length, 0, JSON.stringify(c.json.violations).slice(0, 300))
  assert.match(c.first, /^No ARIA violations found .*within #clean/)
})

test('check_aria html + selector scopes the snippet the same way', async () => {
  const r = await call('check_aria', { html: '<div id="a"><button aria-pressed="maybe">x</button></div><div id="b"><button>y</button></div>', selector: '#b' })
  assert.equal(r.json.violations.length, 0, r.text.slice(0, 300))
})

test('check_aria: selector that matches nothing is an honest error, not "no violations"', async () => {
  const r = await call('check_aria', { url: `${base}/`, selector: '#nope' })
  assert.equal(r.isError, true)
  assert.match(r.first, /matches no element/)
  assert.doesNotMatch(r.first, /No ARIA violations/)
})

test('check_aria: unreachable url and HTTP 403 are errors, never a clean result', async () => {
  const dead = await call('check_aria', { url: 'http://127.0.0.1:9/' })
  assert.equal(dead.isError, true)
  assert.match(dead.first, /^check_aria failed:/)
  const forbidden = await call('check_aria', { url: `${base}/403` })
  assert.equal(forbidden.isError, true)
  assert.match(forbidden.first, /HTTP 403/)
})

test('check_aria: needs exactly one of html / url', async () => {
  const none = await call('check_aria', {})
  assert.equal(none.isError, true)
  assert.match(none.first, /^Error: pass `html`.*or `url`/)
  const both = await call('check_aria', { html: '<p>x</p>', url: `${base}/` })
  assert.equal(both.isError, true)
  assert.match(both.first, /not both/)
})

test('check_aria strict args: url / selector / tunnel_secret accepted, unknown keys still refused', () => {
  const strict = (serverMod as any).strictArgError
  assert.equal(strict('check_aria', { url: 'https://x.test', selector: '#a', tunnel_secret: 's', nodeLimit: 5 }), null)
  assert.match(String(strict('check_aria', { bogus: 1 })), /unknown argument 'bogus'/)
})

// ---- check_color_contrast ------------------------------------------------

test('check_color_contrast url + selector: reads the element\'s own colors', async () => {
  const r = await call('check_color_contrast', { url: `${base}/`, selector: '#low', brandColors: ['#333333'] })
  assert.equal(r.isError, false, r.text)
  assert.match(r.text, /#999999 on #ffffff/)
  assert.match(r.text, /WCAG AA {2}\(≥ 4\.5\): FAIL/)
  assert.match(r.text, /read from #low on /)
})

test('check_color_contrast url + selector: background comes from the nearest painted ancestor', async () => {
  const r = await call('check_color_contrast', { url: `${base}/`, selector: '#onblack' })
  assert.match(r.text, /#777777 on #000000/)
  assert.match(r.text, /WCAG AA {2}\(≥ 4\.5\): PASS/)
})

test('check_color_contrast: gradient / image background is an honest error, not a guessed ratio', async () => {
  const r = await call('check_color_contrast', { url: `${base}/`, selector: '#ongrad' })
  assert.equal(r.isError, true)
  assert.match(r.first, /gradient or image/)
  assert.match(r.first, /pass `background`/)
})

test('check_color_contrast: explicit colors win over the page', async () => {
  const r = await call('check_color_contrast', { foreground: '#000000', background: '#ffffff', url: `${base}/`, selector: '#low' })
  assert.match(r.text, /Contrast ratio: 21\.00:1/)
})

test('check_color_contrast: selector with no match, unreachable url, and missing colors are errors', async () => {
  const miss = await call('check_color_contrast', { url: `${base}/`, selector: '#nope' })
  assert.equal(miss.isError, true)
  assert.match(miss.first, /matches no element/)
  const dead = await call('check_color_contrast', { url: 'http://127.0.0.1:9/', selector: '#low' })
  assert.equal(dead.isError, true)
  assert.match(dead.first, /^check_color_contrast failed:/)
  const none = await call('check_color_contrast', { url: `${base}/` })
  assert.equal(none.isError, true)
  assert.match(none.first, /foreground and background.*or `url` \+ `selector`/)
})

// ---- hosted ---------------------------------------------------------------

test('hosted: both tools advertise url + selector (+ tunnel_secret) and refuse loopback', async () => {
  const tools = (await (await client(true)).listTools()).tools
  for (const name of ['check_aria', 'check_color_contrast']) {
    const t = tools.find((x) => x.name === name)!
    const props = (t.inputSchema as any).properties
    for (const k of ['url', 'selector', 'tunnel_secret']) assert.ok(k in props, `${name} advertises ${k}`)
    assert.deepEqual((t.inputSchema as any).required ?? [], [], `${name}: nothing required — the handler checks the combinations`)
  }
  const r = await call('check_aria', { url: `${base}/` }, true)
  assert.equal(r.isError, true)
  assert.match(r.first, /localhost|private/i)
})

test('anonymous hosted gate: url + selector on check_color_contrast is heavy even with brandColors', () => {
  assert.equal(anonLimitClass({ name: 'check_color_contrast', args: { url: 'https://x.test', selector: '#a', brandColors: ['#0055aa'] } }), 'heavy')
  assert.equal(anonLimitClass({ name: 'check_aria', args: { url: 'https://x.test' } }), 'heavy')
})

test('check_color_contrast: oklch colors and ancestor opacity are measured, not refused or overstated', async () => {
  const page = `<!doctype html><html><body style="background:#fff">
    <p id="ok" style="color:oklch(0 0 0)">oklch black</p>
    <div style="opacity:0.3"><p id="faded" style="color:#000000">faded</p></div></body></html>`
  const srv = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page) })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const u = `http://127.0.0.1:${(srv.address() as any).port}/`
  try {
    const ok = await call('check_color_contrast', { url: u, selector: '#ok', brandColors: ['#000000'] })
    assert.equal(ok.isError, false, ok.text)
    assert.match(ok.text, /#000000 on #ffffff/)
    const faded = await call('check_color_contrast', { url: u, selector: '#faded', brandColors: ['#000000'] })
    assert.match(faded.text, /WCAG AA {2}\(≥ 4\.5\): FAIL/, faded.text)
  } finally {
    srv.close()
  }
})

// Codex P1 on #117: CSS opacity composites the whole rendered group (text AND
// its painted background) against the backdrop. White text on black with
// opacity .5 over white renders white-ish on gray (~3.95:1, AA FAIL), not
// gray on black (~5.32:1, PASS).
test('check_color_contrast: opacity composites text and background together', async () => {
  const page = `<!doctype html><html><body style="background:#ffffff;margin:0">
    <div id="half" style="background:#000000;color:#ffffff;opacity:0.5;font-size:16px">half</div>
    <div style="opacity:0.5"><div style="background:#000000"><span id="nested" style="color:#ffffff;font-size:16px">nested</span></div></div>
    <div style="background:#000000"><span id="plain" style="color:#ffffff;opacity:0.5">plain</span></div></body></html>`
  const srv = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page) })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const u = `http://127.0.0.1:${(srv.address() as any).port}/`
  try {
    for (const sel of ['#half', '#nested']) {
      const r = await call('check_color_contrast', { url: u, selector: sel, brandColors: ['#000000'] })
      assert.match(r.text, /#ffffff on #80808[0-1]|#ffffff on #7f7f7f/, `${sel}: ${r.text}`)
      assert.match(r.text, /WCAG AA {2}\(≥ 4\.5\): FAIL/, `${sel}: ${r.text}`)
    }
    // Opacity only on the text: the text fades, its ancestor's background does not.
    const plain = await call('check_color_contrast', { url: u, selector: '#plain', brandColors: ['#000000'] })
    assert.match(plain.text, /#80808[0-1] on #000000|#7f7f7f on #000000/, plain.text)
  } finally {
    srv.close()
  }
})
