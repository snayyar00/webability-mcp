/**
 * Friction wave 2 — get_rules argument aliases (24/24 personas guessed wrong
 * names: wcag / level / criterion / rule / ruleId / category / filter / query).
 * Aliases map onto the canonical args; canonical wins; unknown args still
 * error naming the valid keys.
 */
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { resolveGetRulesArgs } from '../src/getRulesArgs.ts'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

process.env.WEBABILITY_SCAN_LOG_DIR = mkdtempSync(join(tmpdir(), 'wa-alias-'))
const { createServer } = await import('../src/server.ts')

async function connect() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}
const call = async (args: Record<string, unknown>) => (await connect()).callTool({ name: 'get_rules', arguments: args }) as Promise<any>
const text = (res: any) => String(res.content[0].text)
const rules = (res: any) => JSON.parse(String(res.content[1].text).replace(/^```json\n|\n```$/g, '')) as any[]
const ids = (res: any) => rules(res).map((r) => r.ruleId).sort()

test('wcag criterion alias ("1.4.3") filters like tags ["wcag143"]', async () => {
  const viaAlias = await call({ wcag: '1.4.3' })
  const canonical = await call({ tags: ['wcag143'] })
  assert.ok(!viaAlias.isError, text(viaAlias))
  assert.ok(rules(viaAlias).length > 0)
  assert.deepEqual(ids(viaAlias), ids(canonical))
})

test('criterion alias behaves like wcag alias', async () => {
  assert.deepEqual(ids(await call({ criterion: '1.4.3' })), ids(await call({ tags: ['wcag143'] })))
})

test('level alias, case/whitespace tolerant', async () => {
  const res = await call({ level: ' aa ' })
  assert.ok(!res.isError, text(res))
  const r = rules(res)
  assert.ok(r.length >= 7, `got ${r.length}`)
  assert.ok(r.every((x) => x.tags.some((t: string) => /^wcag2(1|2)?aa$/.test(t))))
})

test('category / filter / tag aliases map to tags (string or array)', async () => {
  const want = ids(await call({ tags: ['best-practice'] }))
  assert.deepEqual(ids(await call({ category: 'best-practice' })), want)
  assert.deepEqual(ids(await call({ filter: ['best-practice'] })), want)
  assert.deepEqual(ids(await call({ tag: ['best-practice'] })), want)
})

test('rule / ruleId / query alias selects by rule id, case, whitespace and -/_ insensitive', async () => {
  for (const a of [{ rule: 'color-contrast' }, { ruleId: ' Color_Contrast ' }, { query: 'COLOR-CONTRAST' }]) {
    const res = await call(a)
    assert.ok(!res.isError, text(res))
    const r = rules(res)
    assert.ok(r.some((x) => x.ruleId === 'color-contrast'), JSON.stringify(a))
    assert.ok(r.length < 15, `expected a narrow list, got ${r.length}`)
  }
})

test('alias + canonical both given: canonical wins', async () => {
  const both = await call({ tags: ['wcag2aa'], wcag: '1.4.3', level: 'AAA' })
  assert.deepEqual(ids(both), ids(await call({ tags: ['wcag2aa'] })))
  const rr = await call({ rule: 'color-contrast', ruleId: 'image-alt' })
  assert.ok(rules(rr).some((x) => x.ruleId === 'color-contrast'))
  assert.ok(!rules(rr).some((x) => x.ruleId === 'image-alt'))
})

test('wrong-type alias values are errors naming the arg', async () => {
  for (const [k, v] of [['level', 5], ['wcag', { a: 1 }], ['rule', ['x']], ['ruleId', 3]] as const) {
    const res = await call({ [k]: v })
    assert.equal(res.isError, true, k)
    assert.match(text(res), new RegExp(`^Error: ${k} must be`))
  }
})

test('unknown level value is an error listing A | AA | AAA', async () => {
  const res = await call({ level: 'platinum' })
  assert.equal(res.isError, true)
  assert.match(text(res), /A \| AA \| AAA/)
})

test('empty-string alias values are ignored (same as omitted)', async () => {
  const all = await call({})
  assert.equal(rules(await call({ rule: '', level: '', wcag: '  ' })).length, rules(all).length)
})

test('unknown arg errors naming it and the valid keys (including rule)', async () => {
  const res = await call({ bogus: 1 })
  assert.equal(res.isError, true)
  assert.match(text(res), /^Error: unknown argument 'bogus'/)
  assert.match(text(res), /tags, rule, fixability, engine/)
})

test('wcag / criterion "AA" expands like level (no silent zero-rule result)', () => {
  for (const k of ['wcag', 'criterion']) {
    assert.deepEqual(resolveGetRulesArgs({ [k]: 'AA' }).tags, ['wcag2aa', 'wcag21aa', 'wcag22aa'], k)
  }
})
