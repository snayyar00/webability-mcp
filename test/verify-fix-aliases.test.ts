/**
 * Friction wave 2 — verify_fix arg aliases (22/24 personas passed the issue /
 * rule / page under another name; the tool silently ignored it and reported a
 * whole-element verdict). Aliases map onto url/selector/wcag; canonical wins;
 * unknown args are errors. All paths here return before any browser launch.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { resolveVerifyFixArgs, verifyFixTargetUrl } from '../src/verifyFixArgs.ts'
import { describeScanTarget } from '../src/scanLog.ts'

const { createServer } = await import('../src/server.ts')

async function call(args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const res: any = await client.callTool({ name: 'verify_fix', arguments: args })
  return { isError: res.isError, text: res.content.map((x: any) => x.text ?? '').join('\n') }
}
const base = { url: 'https://example.test/', selector: '#q' }

test('rule / ruleId / criterion / id / issue(string) all map to wcag (unknown id => UNVERIFIED)', async () => {
  for (const [k, v] of [['rule', 'no-such-rule-xyz'], ['ruleId', 'no-such-rule-xyz'], ['rule_id', 'no-such-rule-xyz'], ['criterion', 'no-such-rule-xyz'], ['id', 'no-such-rule-xyz'], ['issue', 'no-such-rule-xyz']] as const) {
    const r = await call({ ...base, [k]: v })
    assert.match(r.text, /UNVERIFIED: "no-such-rule-xyz" is not a known rule id/, k)
    assert.equal(r.isError, true, k)
  }
})

test('issue object from scan_page: type becomes the rule, selector fills a missing selector', async () => {
  const r = await call({ url: base.url, issue: { type: 'no-such-rule-xyz', selector: '#from-issue' } })
  assert.match(r.text, /no-such-rule-xyz/)
  assert.match(r.text, /"selector": "#from-issue"/)
})

test('page / pageUrl alias url; element / target alias selector', async () => {
  const r = await call({ page: 'https://example.test/', target: '#q', rule: 'no-such-rule-xyz' })
  assert.match(r.text, /"url": "https:\/\/example.test\/"/)
  assert.match(r.text, /"selector": "#q"/)
  const r2 = await call({ pageUrl: 'https://example.test/', element: '#e', rule: 'no-such-rule-xyz' })
  assert.match(r2.text, /"selector": "#e"/)
})

test('canonical wins over alias', async () => {
  const r = await call({ ...base, wcag: 'canonical-bogus', rule: 'alias-bogus' })
  assert.match(r.text, /"canonical-bogus"/)
  assert.doesNotMatch(r.text, /alias-bogus/)
  const r2 = await call({ url: base.url, selector: '#canon', target: '#alias', wcag: 'x-bogus' })
  assert.match(r2.text, /"selector": "#canon"/)
})

test('case and whitespace around alias values are tolerated', async () => {
  const r = await call({ ...base, rule: '  NO-SUCH-RULE-XYZ  ' })
  assert.match(r.text, /UNVERIFIED: "NO-SUCH-RULE-XYZ" is not a known rule id/)
})

test('wrong-type values are errors naming the arg', async () => {
  for (const [k, v] of [['wcag', 5], ['rule', ['x']], ['selector', 5], ['url', ['u']], ['issue', 7]] as const) {
    const r = await call({ ...base, [k]: v })
    assert.equal(r.isError, true, k)
    assert.match(r.text, new RegExp(`^Error: ${k} must be`), k)
  }
})

test('empty-string selector/url are still required; empty alias is ignored', async () => {
  assert.match((await call({ url: base.url, selector: '', target: '' })).text, /url and selector are required/)
  assert.match((await call({ url: '', selector: '#q', rule: '' })).text, /url and selector are required/)
})

test('unknown arg errors naming it and the valid keys', async () => {
  const r = await call({ ...base, bogus: 1 })
  assert.equal(r.isError, true)
  assert.match(r.text, /^Error: unknown argument 'bogus' — valid keys: url, selector, wcag, viewport/)
})

test('tunnel_secret is accepted (hosted localhost flow injects it into the schema)', () => {
  const r = resolveVerifyFixArgs({ url: 'https://abc.tunnel.webability.io', selector: '#a', tunnel_secret: 's3cret' })
  assert.equal(r.error, undefined)
  assert.equal(r.url, 'https://abc.tunnel.webability.io')
})

test('an empty canonical url falls through to the page alias for the tunnel target', () => {
  const tunnel = 'https://abc.tunnel.webability.io'
  assert.equal(verifyFixTargetUrl({ url: '', page: tunnel, selector: '#a' }), tunnel)
  assert.equal(verifyFixTargetUrl({ url: '  ', pageUrl: tunnel }), tunnel)
  assert.equal(verifyFixTargetUrl({ url: 'https://a.test/', page: tunnel }), 'https://a.test/')
  assert.equal(verifyFixTargetUrl({ selector: '#a' }), undefined)
})

test('scan history / telemetry target uses the resolved url for alias calls', () => {
  assert.equal(describeScanTarget('verify_fix', { page: 'https://a.test/x', selector: '#q' }), 'https://a.test/x')
  assert.equal(describeScanTarget('verify_fix', { url: '', pageUrl: 'https://a.test/y' }), 'https://a.test/y')
  assert.equal(describeScanTarget('verify_fix', { url: 'https://a.test/', page: 'https://b.test/' }), 'https://a.test/')
})
