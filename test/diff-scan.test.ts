/**
 * DEV-1089 item 3: `diff_scan` — baseline vs current → fixed[] / new[] /
 * remaining[]. Page-level complement to verify_fix (which checks one element).
 *
 * Baseline and current can each be a scan_history id (local only) so the tool
 * is testable without a browser; `url` scans live for the current side.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

const dir = mkdtempSync(join(tmpdir(), 'wa-diff-'))
process.env.WEBABILITY_SCAN_LOG_DIR = dir

const { createServer } = await import('../src/server.ts')

async function connect(remote: boolean) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const issue = (id: string, extra: Record<string, unknown> = {}) => ({
  id, impact: 'serious', wcag: '1.1.1', type: 'missing_alt', message: 'Image has no alt', selector: `img#${id}`,
  fix: { attribute: 'alt', currentValue: '', needsManualReview: true }, ...extra,
})

function storeScan(id: string, payload: unknown) {
  writeFileSync(join(dir, `${id}.json`), JSON.stringify({
    id, timestamp: '2026-08-26T00:00:00.000Z', tool: 'scan_page', target: 'https://example.test', durationMs: 1, ok: true, summary: 'x',
    response: { content: [{ type: 'text', text: 'Found …' }, { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' }] },
  }))
}

storeScan('base-1', { url: 'https://example.test', issues: [issue('a'), issue('b'), issue('c', { impact: 'critical' })], incomplete: [issue('q', { confidence: 'needs_review' })] })
storeScan('cur-1', { url: 'https://example.test', issues: [issue('b'), issue('d', { impact: 'minor' })], incomplete: [] })

// HTML_CodeSniffer ids carry the result INDEX, which shifts between scans.
const htmlcs = (id: string, sel: string) => ({ id, impact: 'moderate', wcag: '1.3.1', type: 'H42', message: 'm', selector: sel })
storeScan('hc-base', { url: 'https://example.test', issues: [htmlcs('htmlcs-0-aaa', 'p.x'), htmlcs('htmlcs-1-bbb', 'p.y')], incomplete: [] })
storeScan('hc-cur', { url: 'https://example.test', issues: [htmlcs('htmlcs-0-bbb', 'p.y')], incomplete: [] })

const jsonBlock = (res: any) => JSON.parse(String(res.content[1].text).replace(/^```json\n|\n```$/g, ''))

test('diff_scan is listed on both transports', async () => {
  for (const remote of [false, true]) {
    const { tools } = await (await connect(remote)).listTools()
    const tool = tools.find((t) => t.name === 'diff_scan')
    assert.ok(tool, `diff_scan listed (remote=${remote})`)
  }
})

test('two stored scans → fixed / new / remaining, counted and keyed by issue id', async () => {
  const client = await connect(false)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'base-1', currentId: 'cur-1' } })
  const out = jsonBlock(res)
  assert.deepEqual(out.fixed.map((i: any) => i.id).sort(), ['a', 'c'])
  assert.deepEqual(out.new.map((i: any) => i.id), ['d'])
  assert.deepEqual(out.remaining.map((i: any) => i.id), ['b'])
  assert.deepEqual(out.summary, { baseline: 3, current: 2, fixed: 2, new: 1, remaining: 1 })
  // The first text line is the agent-facing verdict and names the regression.
  assert.match(String(res.content[0].text), /1 new/i)
  assert.match(String(res.content[0].text), /2 fixed/i)
  // New issues carry the structured fix shape too.
  assert.equal(out.new[0].fix.op, 'add-attribute')
  assert.equal(out.new[0].fixability, 'contextual')
})

test('a stored legacy incomplete[] is ignored: never diffed, never counted as fixed', async () => {
  const client = await connect(false)
  const out = jsonBlock(await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'base-1', currentId: 'cur-1' } }))
  assert.equal(out.incompleteResolved, undefined)
  assert.ok(!out.fixed.some((i: any) => i.id === 'q'))
})

test('index-based htmlcs ids are matched by rule+selector, not by the shifting index', async () => {
  const client = await connect(false)
  const out = jsonBlock(await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'hc-base', currentId: 'hc-cur' } }))
  assert.deepEqual(out.fixed.map((i: any) => i.selector), ['p.x'])
  assert.deepEqual(out.new, [])
  assert.deepEqual(out.remaining.map((i: any) => i.selector), ['p.y'])
})

test('an unknown baseline id is an error, not an empty diff', async () => {
  const client = await connect(false)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'nope', currentId: 'cur-1' } })
  assert.match(String(res.content[0].text), /^diff_scan failed:/)
  assert.match(String(res.content[0].text), /nope/)
})

test('missing both a current id and a url is an error', async () => {
  const client = await connect(false)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'base-1' } })
  assert.match(String(res.content[0].text), /^Error:/)
})

test('hosted server has no history, so id-based diffs are refused with the local hint', async () => {
  const client = await connect(true)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'base-1', currentId: 'cur-1' } })
  assert.match(String(res.content[0].text), /npx -y @webability\/mcp/)
})

test('get_rules exposes fixability on every rule and accepts a fixability filter', async () => {
  const client = await connect(false)
  const { tools } = await client.listTools()
  const schema: any = tools.find((t) => t.name === 'get_rules')!.inputSchema
  assert.ok(schema.properties.fixability, 'get_rules has a fixability filter')
  const out = jsonBlock(await client.callTool({ name: 'get_rules', arguments: { fixability: 'visual' } }))
  assert.ok(out.length > 0)
  for (const r of out) assert.equal(r.fixability, 'visual', r.ruleId)
  assert.ok(out.some((r: any) => r.ruleId === 'color-contrast'))
  assert.ok(out.some((r: any) => r.ruleId === 'contrast_insufficient'), 'WebAbility rules are listed alongside axe rules')
})

// Generated ids (Google Sign-In `gsi_<n>_<n>`, Radix/Headless UI/MUI, React
// `:r1:`) change on every load, so the same element showed up as fixed AND new
// when one page was diffed against itself (live, 2026-08-26).
const gsi = (id: string, sel: string) => ({ id, impact: 'moderate', wcag: '4.1.2', type: 'decorative_icon', message: 'm', selector: sel })
storeScan('gen-base', { url: 'https://example.test', issues: [gsi('wa-decorative_icon-111', '#gsi_998949_257892'), gsi('wa-decorative_icon-333', 'div#radix-:r1a:-content > svg')], incomplete: [] })
storeScan('gen-cur', { url: 'https://example.test', issues: [gsi('wa-decorative_icon-222', '#gsi_14672_473841'), gsi('wa-decorative_icon-444', 'div#radix-:r2b:-content > svg')], incomplete: [] })

test('elements whose selector carries a generated id are matched by shape, not by id', async () => {
  const client = await connect(false)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'gen-base', currentId: 'gen-cur' } })
  const p = jsonBlock(res)
  assert.deepEqual(p.summary, { baseline: 2, current: 2, fixed: 0, new: 0, remaining: 2 })
  assert.match(String(res.content[0].text), /No regressions/)
})

// Codex P2 on PR #68: a Set collapses two current findings that normalise to
// the same generated-selector key onto one baseline finding → "No regressions"
// with an extra violation on the page. Diff by count, not by membership.
storeScan('mult-base', { url: 'https://example.test', issues: [gsi('wa-decorative_icon-1', 'div#radix-:r1a:-content > svg')], incomplete: [] })
storeScan('mult-cur', { url: 'https://example.test', issues: [gsi('wa-decorative_icon-2', 'div#radix-:r2b:-content > svg'), gsi('wa-decorative_icon-3', 'div#radix-:r2c:-content > svg')], incomplete: [] })

test('diff keeps baseline multiplicity: an extra equivalent element is NEW', async () => {
  const client = await connect(false)
  const res: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: 'mult-base', currentId: 'mult-cur' } })
  const p = jsonBlock(res)
  assert.deepEqual(p.summary, { baseline: 1, current: 2, fixed: 0, new: 1, remaining: 1 })
  assert.match(String(res.content[0].text), /REGRESSIONS/)
})
