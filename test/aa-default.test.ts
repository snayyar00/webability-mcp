/**
 * Owner decision 2026-10-04: "we don't do AAA" / "always AA". Default scans
 * and check_color_contrast report WCAG AA only; Level AAA appears only when
 * the caller asks (level: "AAA", or a wcag[] entry naming one AAA criterion).
 * Shapes from the persona-round-4 evidence: developer.mozilla.org footer
 * links (target=_blank → 3.2.5 new_window_link) and canada.ca
 * (travel.gc.ca → 3.2.5 external_link_warning).
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import * as oc from '../src/outputControls.ts'
import * as serverMod from '../src/server.ts'

const { createServer } = serverMod
const { filterIssues, parseOutputControls } = oc
const scanLevel = (...a: Parameters<typeof oc.scanLevel>) => oc.scanLevel(...a)

async function call(name: string, args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), cl.connect(c)])
  const r: any = await cl.callTool({ name, arguments: args }, undefined, { timeout: 120_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { isError: r.isError === true, text, json: m ? JSON.parse(m[1]!) : null }
}

const MDN = `<!doctype html><html lang="en"><head><title>Learn web development</title></head><body><main><h1>Learn</h1>
<ul class="footer__socials"><li><a id="mdn-gh" href="https://github.com/mdn/" target="_blank" rel="noopener" aria-label="MDN on GitHub">GitHub</a></li></ul>
<h3><a id="travel" href="https://travel.gc.ca">Travel and tourism</a></h3>
<img src="/hero.png"></main></body></html>`

let http: HttpServer
let base = ''
before(async () => {
  http = createHttpServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(MDN) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

const types = (j: any) => [...(j?.issues ?? []), ...(j?.incomplete ?? [])].map((i: any) => String(i.type))

test('check_color_contrast reports AA only by default', async () => {
  const r = await call('check_color_contrast', { foreground: '#767676', background: '#ffffff' })
  assert.equal(r.isError, false, r.text)
  assert.match(r.text, /WCAG AA {1,2}\(≥ 4\.5\): PASS/)
  assert.doesNotMatch(r.text, /AAA/)
})

test('check_color_contrast shows the AAA verdict when level is "AAA"', async () => {
  const r = await call('check_color_contrast', { foreground: '#767676', background: '#ffffff', level: 'AAA' })
  assert.equal(r.isError, false, r.text)
  assert.match(r.text, /WCAG AAA \(≥ 7\): FAIL/)
})

test('check_color_contrast default never suggests AAA palette colours', async () => {
  const r = await call('check_color_contrast', { foreground: '#999999', background: '#ffffff', brandColors: ['#111111', '#595959'] })
  assert.match(r.text, /passing AA/)
  assert.doesNotMatch(r.text, /AAA/)
})

test('scan_page returns no AAA findings by default (issues, incomplete, summary)', async () => {
  const r = await call('scan_page', { url: base, format: 'json' })
  assert.equal(r.isError, false, r.text)
  const t = types(r.json)
  assert.ok(t.length > 0, 'the fixture still has AA findings (missing alt)')
  assert.deepEqual(t.filter((x) => /new_window_link|external_link_warning/.test(x)), [])
  for (const i of [...(r.json.issues ?? []), ...(r.json.incomplete ?? [])]) assert.notEqual(String(i.wcag), '3.2.5')
  assert.doesNotMatch(r.text, /new_window_link|external_link_warning/)
})

test('scan_page returns AAA findings for level "AAA" and for wcag ["3.2.5"]', async () => {
  const all = await call('scan_page', { url: base, format: 'json', level: 'AAA' })
  assert.ok(types(all.json).includes('new_window_link'), all.text)
  const named = await call('scan_page', { url: base, format: 'json', wcag: ['3.2.5'] })
  assert.ok(types(named.json).includes('new_window_link'), named.text)
})

test('a guideline prefix does not opt into AAA; an exact AAA criterion does', () => {
  assert.equal(scanLevel(parseOutputControls({})), 'AA')
  assert.equal(scanLevel(parseOutputControls({ wcag: ['3.2'] })), 'AA')
  assert.equal(scanLevel(parseOutputControls({ wcag: ['3.2.5'] })), 'AAA')
  assert.equal(scanLevel(parseOutputControls({ level: 'AAA' })), 'AAA')
  assert.equal(scanLevel(parseOutputControls({}), ['wcag2a', 'wcag2aaa']), 'AAA')
  assert.throws(() => parseOutputControls({ level: 'AAAA' }), /level must be one of/)
})

test('filterIssues drops AAA rows unless asked', () => {
  const rows = [{ type: 'new_window_link', wcag: '3.2.5' }, { type: 'missing_alt', wcag: '1.1.1' }, { type: 'contrast_insufficient', wcag: '1.4.3' }]
  assert.deepEqual(filterIssues(rows, parseOutputControls({})).map((r) => r.type), ['missing_alt', 'contrast_insufficient'])
  assert.deepEqual(filterIssues(rows, parseOutputControls({ level: 'AAA' })).map((r) => r.type), ['new_window_link', 'missing_alt', 'contrast_insufficient'])
  assert.deepEqual(filterIssues(rows, parseOutputControls({ wcag: ['3.2.5'] })).map((r) => r.type), ['new_window_link'])
  assert.deepEqual(filterIssues(rows, parseOutputControls({ level: 'A' })).map((r) => r.type), ['missing_alt'])
})

test('scan_html engine "browser" runs axe AAA rules when level is "AAA"', async () => {
  const html = '<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>t</h1><p style="color:#767676;background:#fff">Grey text that passes AA and fails AAA</p></main></body></html>'
  const aa = await call('scan_html', { html, engine: 'browser' })
  assert.doesNotMatch(aa.text, /color-contrast-enhanced/)
  const aaa = await call('scan_html', { html, engine: 'browser', level: 'AAA' })
  assert.match(aaa.text, /color-contrast-enhanced/, aaa.text)
})
