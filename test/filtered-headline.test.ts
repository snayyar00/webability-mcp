/**
 * Persona round 4 (2026-10-03), friction #3 (21/80 runs): with rules / wcag /
 * minImpact active, the headline and `summary` still described the whole
 * page ("Found 67 … Returning 1 issue(s)", summary.total 67). The filtered
 * set leads; the page-wide total is a secondary clause and a separate
 * `pageSummary` field.
 */
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { headingCounts, startCountsFixture, type ScanText } from './_countsFixture.ts'

let fx: Awaited<ReturnType<typeof startCountsFixture>>
let url = ''
let page: ScanText
const scanPage = (extra: Record<string, unknown>) => fx.scanPage(extra)
before(async () => {
  fx = await startCountsFixture()
  url = fx.url
  page = await scanPage({ format: 'json' })
})
after(() => fx?.close())

// ---- 2. filters describe the filtered set ---------------------------------

test('rules filter: headline and summary describe the filtered set; page-wide is secondary', async () => {
  const r = await scanPage({ rules: ['missing_alt'], format: 'json' })
  assert.match(r.headline, /^Found 6 high-confidence issues matching the filters \(rules=\[missing_alt\]\) on /)
  assert.match(r.headline, /Whole page, before filters: 11 issues/)
  assert.equal(r.json.summary.total, 6)
  assert.equal(r.json.summary.serious, 6)
  assert.equal(r.json.pageSummary.total, 11)
  assert.equal(r.json.issuesTotal, 6)
  assert.doesNotMatch(r.headline, /Returning \d+ issue/)
})

test('filter that matches nothing: 0 issues, honest page-wide clause, every format', async () => {
  for (const format of ['json', 'compact']) {
    const r = await scanPage({ rules: ['color-contrast'], format })
    assert.match(r.headline, /^Found 0 high-confidence issues matching the filters/, format)
    assert.match(r.headline, /Whole page, before filters: 11 issues/, format)
    if (format === 'json') {
      assert.equal(r.json.summary.total, 0)
      assert.equal(r.json.pageSummary.total, 11)
    } else {
      assert.deepEqual(headingCounts(r.body), [0])
    }
  }
})

test('minImpact compact: heading count equals the filtered total', async () => {
  const r = await scanPage({ minImpact: 'serious', format: 'compact' })
  const m = r.headline.match(/^Found (\d+) high-confidence issues matching/)
  assert.ok(m, r.headline)
  assert.equal(Number(m[1]), 8)
  assert.deepEqual(headingCounts(r.body), [8])
})

test('scan_html (in-process): filters narrow summary and headline the same way', async () => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js')
  const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js')
  const { createServer } = await import('../src/server.ts')
  const [c, s] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 't', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), client.connect(c)])
  const html = '<main><h1>x</h1><img src="a.png"><img src="b.png"><button></button></main>'
  const call = async (extra: Record<string, unknown>) => {
    const r: any = await client.callTool({ name: 'scan_html', arguments: { html, format: 'json', ...extra } })
    const t = (r.content as any[]).map((x) => String(x.text ?? ''))
    return { headline: t[0]!, json: JSON.parse(t.join('\n').match(/```json\n([\s\S]*?)\n```/)![1]!) }
  }
  const all = await call({})
  assert.ok(all.json.summary.total >= 3, `fixture yields ${all.json.summary.total}`)
  assert.equal(all.json.pageSummary, undefined)
  const one = await call({ rules: ['image-alt'] })
  assert.equal(one.json.summary.total, one.json.issues.length)
  assert.ok(one.json.summary.total > 0 && one.json.summary.total < all.json.summary.total, 'the filter must narrow')
  assert.equal(one.json.pageSummary.total, all.json.summary.total)
  assert.match(one.headline, new RegExp(`^Found ${one.json.summary.total} issue\\(s\\) matching the filters \\(rules=\\[image-alt\\]\\)`))
  assert.match(one.headline, new RegExp(`before filters: ${all.json.summary.total} issue`))
})

test('telemetry keeps recording the page-wide count when filters are on', async () => {
  const { extractSummary } = await import('../src/telemetry.ts')
  const response = { content: [{ type: 'text', text: 'x' }, { type: 'text', text: '```json\n' + JSON.stringify({ summary: { total: 1 }, pageSummary: { total: 67 } }) + '\n```' }] }
  assert.equal(extractSummary(response)?.total, 67)
})
